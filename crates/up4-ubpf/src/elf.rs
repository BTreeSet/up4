//! Turning a committed BPF object into something a VM can execute.
//!
//! `p4c-ubpf` declares each P4 table as a C global (`struct ubpf_map_def
//! pipe_mac_dst = {...}`) and calls `ubpf_map_lookup(&pipe_mac_dst, &key)`, so
//! the compiled object does not contain table *addresses* — it contains
//! relocations against `.data` symbols. Something has to resolve them, and
//! that something is this module.
//!
//! The resolution up4 chooses: rewrite each map reference to the map's
//! **index**, so the running program passes a small integer to the host
//! instead of a pointer. That is what keeps table state on the Rust side —
//! the VM never holds a table address, and the helper receives a value it can
//! check against a closed set rather than dereference.
//!
//! Parse, don't validate: a [`Program`] exists only if the object was a BPF
//! ELF64 whose relocations were all understood. Every rejection is a named
//! [`ElfError`], because the alternative — executing a half-relocated
//! program — is a VM that reads whatever integer happened to be in the
//! instruction stream.
//!
//! Cost: one linear pass over the section headers, one over the symbol table,
//! one over the relocations. Objects here are a few kilobytes, and this runs
//! once per pipeline construction, never per frame.

use std::collections::BTreeMap;

/// ELF constants, named so the checks below read as the claims they are.
mod raw {
    pub const MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
    pub const CLASS64: u8 = 2;
    pub const DATA2LSB: u8 = 1;
    /// `EM_BPF`.
    pub const MACHINE_BPF: u16 = 247;
    pub const SHT_SYMTAB: u32 = 2;
    pub const SHT_REL: u32 = 9;
    /// `R_BPF_64_64`: patches the 64-bit immediate of an `lddw` pair.
    pub const R_BPF_64_64: u32 = 1;
    pub const EHDR_LEN: usize = 64;
    pub const SHDR_LEN: usize = 64;
    pub const SYM_LEN: usize = 24;
    pub const REL_LEN: usize = 16;
    /// One eBPF instruction. `lddw` occupies two.
    pub const INSN_LEN: usize = 8;
    /// `STT_OBJECT`, the symbol type a map definition has.
    pub const STT_OBJECT: u8 = 1;
}

/// Why an object could not be loaded.
///
/// Closed. Each variant is a specific structural claim that failed, so a
/// failure names what was wrong rather than reporting "malformed".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// Not an ELF file at all.
    NotElf,
    /// Not a 64-bit little-endian object.
    NotElf64Le,
    /// Compiled for something other than BPF.
    NotBpf {
        /// The `e_machine` found.
        machine: u16,
    },
    /// Truncated: a header or table ran past the end of the file.
    Truncated {
        /// What was being read.
        what: &'static str,
    },
    /// No `.text`, so there is no program.
    NoText,
    /// A relocation this loader does not implement.
    UnknownRelocation {
        /// The ELF relocation type.
        kind: u32,
    },
    /// A relocation referred to a symbol that is not a map definition. Left
    /// unresolved it would become an arbitrary integer at run time.
    UnresolvedSymbol {
        /// The symbol's name, or its index if the name is unreadable.
        name: String,
    },
    /// A relocation pointed outside `.text`.
    RelocationOutOfRange {
        /// Byte offset the relocation named.
        offset: u64,
    },
}

impl std::fmt::Display for ElfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotElf => write!(f, "not an ELF object"),
            Self::NotElf64Le => write!(f, "not a 64-bit little-endian object"),
            Self::NotBpf { machine } => write!(f, "e_machine {machine} is not BPF (247)"),
            Self::Truncated { what } => write!(f, "truncated while reading {what}"),
            Self::NoText => write!(f, "no .text section: nothing to execute"),
            Self::UnknownRelocation { kind } => {
                write!(f, "relocation type {kind} is not implemented")
            }
            Self::UnresolvedSymbol { name } => {
                write!(
                    f,
                    "relocation against {name}, which is not a map definition"
                )
            }
            Self::RelocationOutOfRange { offset } => {
                write!(f, "relocation at {offset:#x} lies outside .text")
            }
        }
    }
}

impl std::error::Error for ElfError {}

/// A map the program refers to, in the order its index denotes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapRef {
    /// The C symbol, e.g. `pipe_mac_dst` or `pipe_mac_dst_defaultAction`.
    pub symbol: String,
    /// The P4 table it belongs to, with p4c's control prefix removed.
    pub table: String,
    /// Whether this is the table's miss-action map rather than its entries.
    pub is_default: bool,
}

impl MapRef {
    fn new(symbol: String) -> Self {
        // p4c names a map `<control>_<table>`, and the miss-action map
        // `<control>_<table>_defaultAction`.
        let (base, is_default) = match symbol.strip_suffix("_defaultAction") {
            Some(b) => (b.to_owned(), true),
            None => (symbol.clone(), false),
        };
        let table = base
            .split_once('_')
            .map_or(base.clone(), |(_, t)| t.to_owned());
        Self {
            symbol,
            table,
            is_default,
        }
    }
}

/// A loaded, relocated program.
#[derive(Clone, Debug)]
pub struct Program {
    /// `.text`, with every map reference rewritten to that map's index.
    pub text: Vec<u8>,
    /// The maps, indexed by the value now embedded in the instruction stream.
    pub maps: Vec<MapRef>,
}

fn u16le(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at + 2)?.try_into().ok().map(u16::from_le_bytes)
}
fn u32le(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)?.try_into().ok().map(u32::from_le_bytes)
}
fn u64le(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at + 8)?.try_into().ok().map(u64::from_le_bytes)
}

struct Section {
    name: String,
    kind: u32,
    offset: usize,
    size: usize,
    link: u32,
    entsize: usize,
}

/// Parse and relocate a BPF object.
///
/// # Errors
/// [`ElfError`] naming the structural claim that failed.
pub fn load(obj: &[u8]) -> Result<Program, ElfError> {
    if obj.len() < raw::EHDR_LEN || obj.get(..4) != Some(&raw::MAGIC) {
        return Err(ElfError::NotElf);
    }
    if obj[4] != raw::CLASS64 || obj[5] != raw::DATA2LSB {
        return Err(ElfError::NotElf64Le);
    }
    let machine = u16le(obj, 18).ok_or(ElfError::Truncated { what: "e_machine" })?;
    if machine != raw::MACHINE_BPF {
        return Err(ElfError::NotBpf { machine });
    }

    let shoff = u64le(obj, 40).ok_or(ElfError::Truncated { what: "e_shoff" })? as usize;
    let shnum = u16le(obj, 60).ok_or(ElfError::Truncated { what: "e_shnum" })? as usize;
    let shstrndx = u16le(obj, 62).ok_or(ElfError::Truncated { what: "e_shstrndx" })? as usize;

    // Raw section headers first; names need the string table, which is itself
    // a section.
    let mut raws = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let at = shoff + i * raw::SHDR_LEN;
        let get = |o: usize| u64le(obj, at + o).ok_or(ElfError::Truncated { what: "section" });
        raws.push((
            u32le(obj, at).ok_or(ElfError::Truncated { what: "sh_name" })?,
            u32le(obj, at + 4).ok_or(ElfError::Truncated { what: "sh_type" })?,
            get(24)? as usize,
            get(32)? as usize,
            u32le(obj, at + 40).ok_or(ElfError::Truncated { what: "sh_link" })?,
            get(56)? as usize,
        ));
    }
    let strtab = raws
        .get(shstrndx)
        .map(|r| (r.2, r.3))
        .ok_or(ElfError::Truncated { what: "shstrtab" })?;
    let name_at = |off: u32| -> String {
        let start = strtab.0 + off as usize;
        obj.get(start..strtab.0 + strtab.1)
            .and_then(|s| s.split(|b| *b == 0).next())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default()
    };

    let sections: Vec<Section> = raws
        .into_iter()
        .map(|(n, kind, offset, size, link, entsize)| Section {
            name: name_at(n),
            kind,
            offset,
            size,
            link,
            entsize,
        })
        .collect();

    let text_idx = sections
        .iter()
        .position(|s| s.name == ".text")
        .ok_or(ElfError::NoText)?;
    let text_sec = &sections[text_idx];
    let mut text = obj
        .get(text_sec.offset..text_sec.offset + text_sec.size)
        .ok_or(ElfError::Truncated { what: ".text" })?
        .to_vec();

    // Map definitions are the OBJECT symbols, ordered by address within their
    // section, so an index is stable across builds of the same source.
    let symtab = sections.iter().find(|s| s.kind == raw::SHT_SYMTAB);
    let mut symbols: Vec<(u32, String, u8, u64)> = Vec::new();
    if let Some(sym) = symtab {
        let strs = sections.get(sym.link as usize).ok_or(ElfError::Truncated {
            what: "symbol strtab",
        })?;
        let entsize = if sym.entsize == 0 {
            raw::SYM_LEN
        } else {
            sym.entsize
        };
        for i in 0..sym.size / entsize {
            let at = sym.offset + i * entsize;
            let nameoff = u32le(obj, at).ok_or(ElfError::Truncated { what: "st_name" })?;
            let info = *obj
                .get(at + 4)
                .ok_or(ElfError::Truncated { what: "st_info" })?;
            let value = u64le(obj, at + 8).ok_or(ElfError::Truncated { what: "st_value" })?;
            let start = strs.offset + nameoff as usize;
            let name = obj
                .get(start..strs.offset + strs.size)
                .and_then(|s| s.split(|b| *b == 0).next())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .unwrap_or_default();
            #[allow(clippy::cast_possible_truncation)]
            symbols.push((i as u32, name, info & 0xf, value));
        }
    }

    let mut ordered: Vec<&(u32, String, u8, u64)> = symbols
        .iter()
        .filter(|(_, name, ty, _)| *ty == raw::STT_OBJECT && !name.is_empty())
        .collect();
    ordered.sort_by_key(|(_, _, _, value)| *value);
    let index_of: BTreeMap<u32, usize> = ordered
        .iter()
        .enumerate()
        .map(|(i, (sym, _, _, _))| (*sym, i))
        .collect();
    let maps: Vec<MapRef> = ordered
        .iter()
        .map(|(_, name, _, _)| MapRef::new(name.clone()))
        .collect();

    // Apply relocations against `.text`.
    for rel in sections
        .iter()
        .filter(|s| s.kind == raw::SHT_REL && s.name == ".rel.text")
    {
        let entsize = if rel.entsize == 0 {
            raw::REL_LEN
        } else {
            rel.entsize
        };
        for i in 0..rel.size / entsize {
            let at = rel.offset + i * entsize;
            let offset = u64le(obj, at).ok_or(ElfError::Truncated { what: "r_offset" })?;
            let info = u64le(obj, at + 8).ok_or(ElfError::Truncated { what: "r_info" })?;
            #[allow(clippy::cast_possible_truncation)]
            let kind = info as u32;
            #[allow(clippy::cast_possible_truncation)]
            let sym = (info >> 32) as u32;
            if kind != raw::R_BPF_64_64 {
                return Err(ElfError::UnknownRelocation { kind });
            }
            let at_insn =
                usize::try_from(offset).map_err(|_| ElfError::RelocationOutOfRange { offset })?;
            // `lddw` is two instructions: the low half of the immediate lives
            // in the first, the high half in the second.
            if at_insn + 2 * raw::INSN_LEN > text.len() {
                return Err(ElfError::RelocationOutOfRange { offset });
            }
            let Some(&index) = index_of.get(&sym) else {
                let name = symbols
                    .iter()
                    .find(|(i, ..)| *i == sym)
                    .map_or_else(|| sym.to_string(), |(_, n, _, _)| n.clone());
                return Err(ElfError::UnresolvedSymbol { name });
            };
            #[allow(clippy::cast_possible_truncation)]
            let index32 = index as u32;
            text[at_insn + 4..at_insn + 8].copy_from_slice(&index32.to_le_bytes());
            // High half is zero: an index fits in 32 bits, and leaving the
            // compiler's placeholder there would make the helper see garbage
            // in the upper word.
            text[at_insn + raw::INSN_LEN + 4..at_insn + raw::INSN_LEN + 8]
                .copy_from_slice(&0u32.to_le_bytes());
        }
    }

    Ok(Program { text, maps })
}

#[cfg(test)]
mod tests {
    use super::*;

    const L2FWD: &[u8] = include_bytes!("generated/l2fwd.o");
    const L3FWD: &[u8] = include_bytes!("generated/l3fwd.o");

    #[test]
    fn both_committed_objects_load() {
        for (name, obj) in [("l2fwd", L2FWD), ("l3fwd", L3FWD)] {
            let p = load(obj).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(!p.text.is_empty(), "{name} has no code");
            assert_eq!(p.text.len() % raw::INSN_LEN, 0, "{name}: ragged .text");
            assert!(!p.maps.is_empty(), "{name} declares no maps");
        }
    }

    #[test]
    fn each_table_gets_an_entry_map_and_a_default_action_map() {
        let p = load(L2FWD).expect("load");
        let entries: Vec<_> = p.maps.iter().filter(|m| !m.is_default).collect();
        let defaults: Vec<_> = p.maps.iter().filter(|m| m.is_default).collect();
        assert_eq!(entries.len(), 1, "{:?}", p.maps);
        assert_eq!(entries[0].table, "mac_dst");
        assert_eq!(defaults.len(), 1);
        assert_eq!(defaults[0].table, "mac_dst");
    }

    #[test]
    fn l3fwds_table_is_the_route_table() {
        let p = load(L3FWD).expect("load");
        assert!(p.maps.iter().all(|m| m.table == "ipv4_lpm"), "{:?}", p.maps);
    }

    #[test]
    fn relocations_are_replaced_by_map_indices() {
        // The load-bearing claim: after loading, the program refers to maps by
        // a small index, not by an address. Every index must name a real map,
        // or the helper would be handed something it cannot interpret.
        let p = load(L2FWD).expect("load");
        let mut seen = Vec::new();
        for insn in p.text.chunks_exact(raw::INSN_LEN) {
            // `lddw` opcode.
            if insn[0] == 0x18 {
                let imm = u32::from_le_bytes(insn[4..8].try_into().expect("4 bytes"));
                seen.push(imm);
            }
        }
        assert!(!seen.is_empty(), "no lddw found; did the ABI change?");
        for imm in seen {
            assert!(
                (imm as usize) < p.maps.len() || imm == 0,
                "immediate {imm} names no map (have {})",
                p.maps.len()
            );
        }
    }

    #[test]
    fn a_map_symbol_is_split_into_its_table_and_role() {
        let m = MapRef::new("pipe_mac_dst".to_owned());
        assert_eq!(m.table, "mac_dst");
        assert!(!m.is_default);
        let d = MapRef::new("pipe_ipv4_lpm_defaultAction".to_owned());
        assert_eq!(d.table, "ipv4_lpm");
        assert!(d.is_default);
    }

    #[test]
    fn rejections_name_the_claim_that_failed() {
        assert_eq!(load(b"not an elf at all").unwrap_err(), ElfError::NotElf);
        let mut truncated = L2FWD.to_vec();
        truncated[18] = 0xff; // e_machine
        truncated[19] = 0x00;
        assert!(matches!(
            load(&truncated).unwrap_err(),
            ElfError::NotBpf { .. }
        ));
        let mut not64 = L2FWD.to_vec();
        not64[4] = 1;
        assert_eq!(load(&not64).unwrap_err(), ElfError::NotElf64Le);
    }
}
