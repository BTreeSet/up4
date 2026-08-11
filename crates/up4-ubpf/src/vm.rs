//! Executing a loaded program, with the host answering its table lookups.
//!
//! # Getting the program its two arguments
//!
//! p4c emits `entry(void *ctx, struct standard_metadata *std_meta)`, so the
//! program wants two *pointer* registers. No rbpf VM type provides both:
//! `EbpfVmRaw` gives `r1 = mem, r2 = len`, and `EbpfVmMbuff` gives
//! `r1 = mbuff`, expecting the program to load what it needs from that buffer
//! at offsets of its choosing. So up4 supplies an mbuff holding the two
//! pointers and prepends a two-instruction prologue that moves them into
//! place:
//!
//! ```text
//! ldxdw r2, [r1 + 8]   ; &std_meta
//! ldxdw r1, [r1 + 0]   ; ctx
//! ```
//!
//! Order matters — `r1` is the mbuff until the second instruction overwrites
//! it. Prepending is safe because BPF jumps and calls are relative to their
//! own position, and relocations were applied before this.
//!
//! # Where the packet lives
//!
//! `ctx` is never dereferenced by the program: it calls
//! `ubpf_packet_data(ctx)` (helper 9) to get the packet address. So up4 passes
//! a token and the helper returns the real buffer, which keeps frame ownership
//! on the Rust side.
//!
//! # The one `unsafe`
//!
//! rbpf helpers are plain `fn(u64, u64, u64, u64, u64) -> u64` with no context
//! and no borrow of VM memory, so a lookup key arrives as a host address into
//! memory rbpf owns. Reading it is the single `unsafe` in this crate, bounded
//! by the map's declared key width. This is the same trust uBPF's own C
//! runtime takes, and the reason this crate is separate from the
//! `#![forbid(unsafe_code)]` engine.

use std::cell::RefCell;

use crate::elf::Program;
use crate::table::Table;

/// `standard_metadata` as `ubpf_model.p4` declares it, laid out as C does.
pub mod meta {
    /// `input_port`.
    pub const INPUT_PORT: usize = 0;
    /// `packet_length`.
    pub const PACKET_LENGTH: usize = 4;
    /// `output_action`.
    pub const OUTPUT_ACTION: usize = 8;
    /// `output_port`.
    pub const OUTPUT_PORT: usize = 12;
    /// Total size, rounded to the 4-byte alignment of its widest member.
    pub const SIZE: usize = 24;
}

/// The largest value image a lookup can return. Both shipped programs use 8
/// bytes; the margin costs nothing and is asserted against every layout.
const ARENA: usize = 64;

/// Helper indices, as p4c's generated code declares them.
mod helper {
    pub const MAP_LOOKUP: u32 = 1;
    pub const MAP_UPDATE: u32 = 2;
    pub const MAP_DELETE: u32 = 3;
    pub const MAP_ADD: u32 = 4;
    pub const TIME_GET_NS: u32 = 5;
    pub const HASH: u32 = 6;
    pub const PRINTF: u32 = 7;
    pub const ADJUST_HEAD: u32 = 8;
    pub const PACKET_DATA: u32 = 9;
    pub const TRUNCATE_PACKET: u32 = 11;
}

/// What a helper needs, for the duration of one `execute_program`.
///
/// A thread-local because rbpf helpers are bare function pointers with nowhere
/// to carry state. Scoped by [`with_context`], so it is never set outside a
/// single execution on this thread.
struct HelperCtx {
    /// The snapshot this execution reads. Cloned `Arc`, so a control-plane
    /// write during execution cannot change the tables mid-frame.
    tables: std::sync::Arc<Vec<Table>>,
    /// Address and length of the packet buffer, for `ubpf_packet_data`.
    packet: (u64, u64),
    /// Where a looked-up value is placed so the program can read it back.
    /// Owned by the `Vm`, whose lifetime encloses every execution.
    arena: *mut u8,
    /// Set if a helper was asked for something this host does not implement,
    /// so an unsupported program fails loudly instead of forwarding garbage.
    refused: Option<&'static str>,
}

thread_local! {
    static CTX: RefCell<Option<HelperCtx>> = const { RefCell::new(None) };
}

/// Read `len` bytes the VM handed us as an address.
///
/// # Safety
/// `ptr` comes from the running program as an argument to `ubpf_map_lookup`,
/// where p4c always passes the address of a `struct <table>_key` it just
/// constructed on the VM stack, and `len` is that map's declared `key_size`.
/// The program is compiler output from a `.p4` this repository compiled and
/// committed, and its bytecode is checked into the tree, so the pointer is not
/// attacker-controlled: a frame can change the key's *contents*, never its
/// address or width.
unsafe fn read_vm(ptr: u64, len: usize) -> Vec<u8> {
    if ptr == 0 || len == 0 || len > ARENA {
        return Vec::new();
    }
    // SAFETY: as documented above.
    unsafe { std::slice::from_raw_parts(ptr as *const u8, len).to_vec() }
}

fn map_lookup(map: u64, key_ptr: u64, _: u64, _: u64, _: u64) -> u64 {
    CTX.with(|c| {
        let mut slot = c.borrow_mut();
        let Some(ctx) = slot.as_mut() else { return 0 };
        let Some(table) = usize::try_from(map).ok().and_then(|i| ctx.tables.get(i)) else {
            ctx.refused = Some("lookup named a map index the host does not have");
            return 0;
        };
        let width = table.layout().key;
        let key = unsafe { read_vm(key_ptr, width) };
        if key.len() != width {
            ctx.refused = Some("could not read a lookup key of the declared width");
            return 0;
        }
        // A miss must be NULL: it is how the program knows to consult the
        // table's default-action map.
        let Some(value) = table.lookup(&key) else {
            return 0;
        };
        // SAFETY: `arena` is the `Vm`'s own buffer, ARENA bytes long and alive
        // for the whole execution; `value` is at most that (checked by
        // `the_arena_holds_every_value_a_shipped_layout_produces`).
        unsafe {
            std::ptr::copy_nonoverlapping(value.as_ptr(), ctx.arena, value.len().min(ARENA));
        }
        ctx.arena as u64
    })
}

/// `ubpf_adjust_head(ctx, delta)` — grow or shrink the packet's headroom.
///
/// p4c's deparser calls this before emitting. Both shipped programs emit
/// exactly the headers they parsed, so the delta is zero and the packet keeps
/// its address. A non-zero delta would mean encapsulation, which up4's frame
/// layout does not offer from inside the VM (headroom belongs to the harness),
/// so it is refused rather than silently ignored.
fn adjust_head(_: u64, delta: u64, _: u64, _: u64, _: u64) -> u64 {
    if delta != 0 {
        mark_refused("ubpf_adjust_head with a non-zero delta (encapsulation)");
        return 0;
    }
    packet_data(0, 0, 0, 0, 0)
}

fn packet_data(_: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    CTX.with(|c| c.borrow().as_ref().map_or(0, |ctx| ctx.packet.0))
}

fn mark_refused(what: &'static str) {
    CTX.with(|c| {
        if let Some(ctx) = c.borrow_mut().as_mut() {
            ctx.refused = Some(what);
        }
    });
}

/// Every helper p4c may emit a call to but up4 does not implement.
///
/// Answering zero silently would let a program mis-forward; recording a
/// refusal turns the frame into a drop with a reason instead. rbpf takes a
/// bare `fn`, which cannot capture, so each refusal is its own function —
/// the macro keeps that from becoming eight copies of the same body.
macro_rules! refusals {
    ($($name:ident => $what:literal),* $(,)?) => {
        $(fn $name(_: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
            mark_refused($what);
            0
        })*
    };
}

refusals! {
    refuse_map_update => "ubpf_map_update from the data plane",
    refuse_map_delete => "ubpf_map_delete from the data plane",
    refuse_map_add => "ubpf_map_add from the data plane",
    refuse_time => "ubpf_time_get_ns",
    refuse_hash => "ubpf_hash",
    refuse_printf => "ubpf_printf",
    refuse_truncate => "ubpf_truncate_packet",
}

/// A program loaded into a VM, ready to execute frames.
pub struct Vm {
    vm: rbpf::EbpfVmMbuff<'static>,
    mbuff: Vec<u8>,
    meta: Vec<u8>,
    packet: Vec<u8>,
    arena: Vec<u8>,
}

/// What one execution decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Whether the program passed the frame.
    pub pass: bool,
    /// `std_meta.output_port` as the program left it.
    pub output_port: u32,
    /// The frame's length after deparse.
    pub len: usize,
}

/// Why a program could not be prepared or run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmError {
    /// rbpf refused the bytecode.
    Rejected(String),
    /// A helper the host does not implement was called.
    Refused(&'static str),
    /// The frame does not fit the buffer this VM was built for.
    FrameTooLong {
        /// Bytes offered.
        got: usize,
        /// Bytes the buffer holds.
        cap: usize,
    },
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(e) => write!(f, "bytecode rejected: {e}"),
            Self::Refused(w) => write!(f, "unsupported: {w}"),
            Self::FrameTooLong { got, cap } => write!(f, "frame of {got} exceeds {cap}"),
        }
    }
}

impl std::error::Error for VmError {}

/// The two-instruction prologue that moves the mbuff's contents into the
/// registers `entry` expects. See the module docs.
fn prologue() -> [u8; 16] {
    // ldxdw r2, [r1 + 8] : opcode 0x79, regs (dst=2, src=1) -> 0x12, off=8
    // ldxdw r1, [r1 + 0] : opcode 0x79, regs (dst=1, src=1) -> 0x11, off=0
    let mut p = [0u8; 16];
    p[0] = 0x79;
    p[1] = 0x12;
    p[2..4].copy_from_slice(&8i16.to_le_bytes());
    p[8] = 0x79;
    p[9] = 0x11;
    p[10..12].copy_from_slice(&0i16.to_le_bytes());
    p
}

impl Vm {
    /// Prepare `program` to run frames of at most `mtu` bytes.
    ///
    /// # Errors
    /// [`VmError::Rejected`] if rbpf will not accept the bytecode.
    pub fn new(program: &Program, mtu: usize) -> Result<Self, VmError> {
        let mut text = Vec::with_capacity(16 + program.text.len());
        text.extend_from_slice(&prologue());
        text.extend_from_slice(&program.text);
        // rbpf borrows the program for the VM's lifetime. Leaking is bounded
        // and deliberate: a handful of kilobytes, once per pipeline, for the
        // life of the process — cheaper than a self-referential struct.
        let text: &'static [u8] = Box::leak(text.into_boxed_slice());

        let mut vm =
            rbpf::EbpfVmMbuff::new(Some(text)).map_err(|e| VmError::Rejected(e.to_string()))?;
        let reg =
            |vm: &mut rbpf::EbpfVmMbuff<'static>, k, f: fn(u64, u64, u64, u64, u64) -> u64| {
                vm.register_helper(k, f)
                    .map_err(|e| VmError::Rejected(e.to_string()))
            };
        reg(&mut vm, helper::MAP_LOOKUP, map_lookup)?;
        reg(&mut vm, helper::PACKET_DATA, packet_data)?;
        reg(&mut vm, helper::ADJUST_HEAD, adjust_head)?;
        // The control plane owns table contents, so the data plane must not
        // mutate them; the rest are simply not implemented.
        for (k, f) in [
            (
                helper::MAP_UPDATE,
                refuse_map_update as fn(u64, u64, u64, u64, u64) -> u64,
            ),
            (helper::MAP_DELETE, refuse_map_delete),
            (helper::MAP_ADD, refuse_map_add),
            (helper::TIME_GET_NS, refuse_time),
            (helper::HASH, refuse_hash),
            (helper::PRINTF, refuse_printf),
            (helper::TRUNCATE_PACKET, refuse_truncate),
        ] {
            reg(&mut vm, k, f)?;
        }

        let mut this = Self {
            vm,
            mbuff: vec![0u8; 16],
            meta: vec![0u8; meta::SIZE],
            packet: vec![0u8; mtu],
            arena: vec![0u8; ARENA],
        };
        // Heap buffers do not move when the struct does, so these ranges are
        // stable for the VM's life and are registered once rather than per
        // frame — an interpreter check list that grew every frame would be a
        // leak with a performance tail.
        for (ptr, len) in [
            (this.packet.as_ptr() as u64, this.packet.len() as u64),
            (this.meta.as_ptr() as u64, meta::SIZE as u64),
            (this.arena.as_ptr() as u64, ARENA as u64),
        ] {
            this.vm.register_allowed_memory(ptr..ptr + len);
        }
        Ok(this)
    }

    /// Run one frame. `frame` is copied in and the result copied back out.
    ///
    /// # Errors
    /// [`VmError`] if the frame does not fit, a helper was refused, or the VM
    /// faulted.
    pub fn run(
        &mut self,
        frame: &[u8],
        ingress: u16,
        tables: &std::sync::Arc<Vec<Table>>,
    ) -> Result<Outcome, VmError> {
        if frame.len() > self.packet.len() {
            return Err(VmError::FrameTooLong {
                got: frame.len(),
                cap: self.packet.len(),
            });
        }
        self.packet[..frame.len()].copy_from_slice(frame);

        self.meta.fill(0);
        let len32 = u32::try_from(frame.len()).unwrap_or(u32::MAX);
        self.meta[meta::INPUT_PORT..meta::INPUT_PORT + 4]
            .copy_from_slice(&u32::from(ingress).to_le_bytes());
        self.meta[meta::PACKET_LENGTH..meta::PACKET_LENGTH + 4]
            .copy_from_slice(&len32.to_le_bytes());

        // The mbuff carries the two pointers the prologue loads.
        let ctx_token = 1u64; // never dereferenced; helper 9 answers for it
        let meta_ptr = self.meta.as_ptr() as u64;
        self.mbuff[..8].copy_from_slice(&ctx_token.to_le_bytes());
        self.mbuff[8..16].copy_from_slice(&meta_ptr.to_le_bytes());

        let packet_ptr = self.packet.as_ptr() as u64;
        let packet_len = self.packet.len() as u64;
        let arena_ptr = self.arena.as_mut_ptr();

        let (result, refused) = with_context(
            HelperCtx {
                tables: std::sync::Arc::clone(tables),
                packet: (packet_ptr, packet_len),
                arena: arena_ptr,
                refused: None,
            },
            || {
                self.vm
                    .execute_program(&self.packet, &self.mbuff)
                    .map_err(|e| VmError::Rejected(e.to_string()))
            },
        );
        if let Some(what) = refused {
            return Err(VmError::Refused(what));
        }
        let pass = result? != 0;

        let out_port = u32::from_le_bytes(
            self.meta[meta::OUTPUT_PORT..meta::OUTPUT_PORT + 4]
                .try_into()
                .expect("4 bytes"),
        );
        let len = u32::from_le_bytes(
            self.meta[meta::PACKET_LENGTH..meta::PACKET_LENGTH + 4]
                .try_into()
                .expect("4 bytes"),
        ) as usize;
        Ok(Outcome {
            pass,
            output_port: out_port,
            len: len.min(self.packet.len()),
        })
    }

    /// The frame as the program left it.
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }
}

/// Install `ctx` for the duration of `f`, then take it back down.
///
/// Scoping the thread-local this way is what makes the helpers' reliance on it
/// sound: it is set only around one execution, and cleared even if `f` returns
/// early.
fn with_context<R>(ctx: HelperCtx, f: impl FnOnce() -> R) -> (R, Option<&'static str>) {
    CTX.with(|c| *c.borrow_mut() = Some(ctx));
    let out = f();
    let refused = CTX.with(|c| c.borrow_mut().take().and_then(|ctx| ctx.refused));
    (out, refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prologue_is_two_loads_from_the_mbuff() {
        let p = prologue();
        assert_eq!(p[0], 0x79, "ldxdw");
        assert_eq!(p[1], 0x12, "dst r2, src r1");
        assert_eq!(i16::from_le_bytes([p[2], p[3]]), 8, "&std_meta at +8");
        assert_eq!(p[8], 0x79);
        assert_eq!(p[9], 0x11, "dst r1, src r1");
        assert_eq!(i16::from_le_bytes([p[10], p[11]]), 0, "ctx at +0");
    }

    #[test]
    fn the_arena_holds_every_value_a_shipped_layout_produces() {
        for l in [
            crate::table::Layout::scalar(8, 2),
            crate::table::Layout::scalar(4, 8),
        ] {
            assert!(l.value <= ARENA, "{l:?} does not fit the arena");
        }
    }
}

#[cfg(test)]
mod exec_tests {
    use super::*;
    use crate::table::{Layout, Match, Table};
    use std::sync::Arc;

    /// Build the table set a program's maps imply. Entry maps start empty (a
    /// miss must be NULL); default-action maps answer `action` unconditionally.
    fn tables_for(prog: &Program, action: u32, params: &[u8]) -> Arc<Vec<Table>> {
        Arc::new(
            prog.maps
                .iter()
                .map(|m| {
                    if m.is_default {
                        // p4c gives the default map a uint32 key.
                        let l = Layout::scalar(4, 2);
                        Table::new(Match::Exact, l, Some(l.value(action, params)))
                    } else {
                        Table::new(Match::Exact, Layout::scalar(8, 2), None)
                    }
                })
                .collect(),
        )
    }

    fn frame() -> Vec<u8> {
        let mut f = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]; // dst
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // src
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        f.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        f
    }

    /// The load-bearing test for this whole backend: compiler-produced
    /// bytecode, loaded from the committed object, executes and reaches the
    /// action its table named.
    #[test]
    fn the_bytecode_executes_and_takes_the_default_action() {
        let prog = crate::elf::load(include_bytes!("generated/l2fwd.o")).expect("load");
        let mut vm = Vm::new(&prog, 2048).expect("prepare");
        // `forward` is action 0 in `enum mac_dst_0_actions`.
        let tables = tables_for(&prog, 0, &7u16.to_le_bytes());
        let out = vm.run(&frame(), 0, &tables).expect("run");
        assert!(out.pass, "the program passed the frame");
        assert_eq!(out.output_port, 7, "forward(7) reached std_meta");
    }

    #[test]
    fn the_broadcast_action_sets_the_reserved_port() {
        let prog = crate::elf::load(include_bytes!("generated/l2fwd.o")).expect("load");
        let mut vm = Vm::new(&prog, 2048).expect("prepare");
        // `broadcast` is action 1, and the .p4 writes up4's reserved 65534.
        let tables = tables_for(&prog, 1, &[]);
        let out = vm.run(&frame(), 0, &tables).expect("run");
        assert!(out.pass);
        assert_eq!(out.output_port, 65534);
    }

    #[test]
    fn the_drop_action_does_not_pass() {
        let prog = crate::elf::load(include_bytes!("generated/l2fwd.o")).expect("load");
        let mut vm = Vm::new(&prog, 2048).expect("prepare");
        let tables = tables_for(&prog, 2, &[]); // `drop`
        let out = vm.run(&frame(), 0, &tables).expect("run");
        assert!(!out.pass, "drop must not pass the frame");
    }

    #[test]
    fn a_frame_larger_than_the_buffer_is_refused_not_truncated() {
        let prog = crate::elf::load(include_bytes!("generated/l2fwd.o")).expect("load");
        let mut vm = Vm::new(&prog, 64).expect("prepare");
        let tables = tables_for(&prog, 1, &[]);
        assert!(matches!(
            vm.run(&[0u8; 128], 0, &tables),
            Err(VmError::FrameTooLong { .. })
        ));
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;
    use crate::table::{Layout, Match, Table};
    use std::sync::Arc;

    /// The key encoding, settled by experiment.
    ///
    /// p4c stores `hdr.ethernet.dst` (a `bit<48>`) in a `uint64_t`, reading
    /// the field as a **big-endian number** and holding it in native byte
    /// order. So `aa:bb:cc:dd:ee:ff` on the wire is the integer
    /// `0x0000_aabb_ccdd_eeff`, whose key image is that integer's
    /// little-endian bytes.
    ///
    /// Two other plausible encodings — the byte-reversed integer, and the wire
    /// bytes copied straight in — are asserted *not* to match, because a test
    /// that only checked the positive case would pass under more than one
    /// convention and settle nothing.
    #[test]
    fn a_mac_key_is_the_wire_bytes_read_as_a_big_endian_number() {
        const WIRE: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let correct = 0x0000_aabb_ccdd_eeffu64.to_le_bytes();
        let reversed = 0xffee_ddcc_bbaa_0000u64.to_le_bytes();
        let raw = [WIRE[0], WIRE[1], WIRE[2], WIRE[3], WIRE[4], WIRE[5], 0, 0];

        assert!(forwards_to_9(&correct), "the settled encoding must hit");
        assert!(!forwards_to_9(&reversed), "byte-reversed must not hit");
        assert!(!forwards_to_9(&raw), "raw wire bytes must not hit");
    }

    /// Install one entry under `key` and report whether a frame to
    /// `aa:bb:cc:dd:ee:ff` reached `forward(9)`.
    fn forwards_to_9(key: &[u8; 8]) -> bool {
        let prog = crate::elf::load(include_bytes!("generated/l2fwd.o")).expect("load");
        let entry = Layout::scalar(8, 2);
        let tables: Vec<Table> = prog
            .maps
            .iter()
            .map(|m| {
                if m.is_default {
                    let d = Layout::scalar(4, 2);
                    // `drop`, so only a real hit can produce a pass.
                    Table::new(Match::Exact, d, Some(d.value(2, &[])))
                } else {
                    let mut t = Table::new(Match::Exact, entry, None);
                    t.insert(key, 0, entry.value(0, &9u16.to_le_bytes()));
                    t
                }
            })
            .collect();
        let mut vm = Vm::new(&prog, 2048).expect("prepare");
        let mut f = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00, 0xde, 0xad]);
        let out = vm.run(&f, 0, &Arc::new(tables)).expect("run");
        out.pass && out.output_port == 9
    }
}
