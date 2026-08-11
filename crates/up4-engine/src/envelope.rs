//! The envelope around a P4 program: what up4 does before it sees a frame, and
//! what up4 does to a frame it decided to send.
//!
//! ```text
//!     up4(program) = admit(program) ; p4(program) ; scrub(program)
//! ```
//!
//! Both ends are up4's, not P4's, and both are declared on the
//! [`Program`](crate::catalog::Program) rather than on a backend — see below.
//!
//! # Why neither end is in the `.p4`, and neither is in a backend
//!
//! A P4 parser rejects for exactly one reason: `extract` ran out of bytes. It
//! never checks that the bytes it took agree with each other. So "the IPv4
//! header does not contradict itself" — version 4, a header length that is
//! legal and actually present — has no expression in either `.p4` of record,
//! and adding one would either fail to compile on x4c or make the two
//! bindings diverge from each other.
//!
//! up4 wants the check anyway: a well-formed packet never reaches it, and a
//! malformed one is cheaper to refuse at ingress than to carry through a table
//! lookup and a rewrite.
//!
//! At the other end, up4 zero-fills the checksums inside a frame it modified
//! (spec S1.5). A P4 program cannot express that either: the `.p4` zeroes
//! `hdr.ipv4.hdr_checksum` because that field is one it writes, but the
//! transport checksum lives in bytes the program never parses, so no
//! deparser emits it.
//!
//! Putting it inside *one* backend is what must not happen. Three renderings
//! of one program that disagree about which frames they refuse are three
//! programs. So the check is declared on the [`Program`](crate::catalog::Program)
//! and composed with whichever backend runs it:
//!
//! ```text
//!     up4(program) = admit(program) ; p4(program)
//! ```
//!
//! Every backend computes that same composition. The `native` rendering fuses
//! both ends into its own code — `admit` is already `Ipv4::parse`'s
//! precondition and `scrub` is already its deparser's last statement, so
//! running either again would be a redundant pass over the same bytes — while
//! the compiled backends, whose programs are opaque, compose them explicitly
//! through [`Enveloped`]. Same function, two factorizations; the conformance
//! corpus and the end-to-end tests hold the fusion honest, and
//! `fusion_is_sound_for_every_version_and_ihl` below proves the ingress half
//! pointwise.

use crate::headers::{ETH_HDR_LEN, ETHERTYPE_IPV4, Ethernet, Ipv4, zero_inner_checksums};
use crate::{Engine, FrameCtx, Pipeline, TableOps, Verdict};

/// What a program refuses at ingress, before its parser runs.
///
/// A closed sum rather than a predicate object: the alternatives are a fixed,
/// reviewable list, each attached to the kind of program that wants it, and
/// `Everything` is a real variant rather than a `None` that reads as an
/// oversight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Nothing is refused here; the program's own parser is the only gate.
    ///
    /// A bridge forwards on MAC addresses and has no opinion about the payload
    /// — refusing a malformed IPv4 packet would be a routing decision made by
    /// a program that does not route.
    Everything,
    /// A frame announcing `ethertype == 0x0800` must carry an IPv4 header that
    /// does not contradict itself: version 4, and a header length that is at
    /// least the legal minimum and lies inside the captured bytes.
    ///
    /// A router acts on that header, so one that disagrees with itself is a
    /// packet up4 declines to route (docs/deviations.md D10). Frames that are
    /// not IPv4 pass through untouched — refusing them is the program's job,
    /// not this one's.
    CoherentIpv4,
}

/// What up4 does to a frame the program decided to send.
///
/// A closed sum for the same reason [`Admission`] is one: the alternatives are
/// a fixed list, and "does nothing" is a named choice rather than a missing
/// case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scrub {
    /// Nothing. A program that modifies no header leaves every checksum
    /// exactly as valid — or as invalid — as it found it, and rewriting one it
    /// did not invalidate would corrupt a frame the switch did not touch.
    Nothing,
    /// Zero the IPv4 header checksum and the transport checksum it contains
    /// (spec S1.5).
    ///
    /// up4 never computes or verifies an inner checksum, so a program that
    /// edits a header must not leave a stale checksum behind that a receiver
    /// could mistake for a valid one. This is the harness's *only*
    /// inner-packet modification.
    InnerChecksums,
}

impl Scrub {
    /// Apply this to a frame on its way out. Total, and `O(1)`.
    pub fn apply(self, frame: &mut [u8]) {
        match self {
            Self::Nothing => {}
            Self::InnerChecksums => zero_inner_checksums(frame),
        }
    }
}

impl Admission {
    /// Whether `frame` may reach the program. Total, and `O(1)`: at most one
    /// Ethernet and one IPv4 header parse, no allocation.
    #[must_use]
    pub fn admits(self, frame: &[u8]) -> bool {
        match self {
            Self::Everything => true,
            Self::CoherentIpv4 => match Ethernet::parse(frame) {
                // Not IPv4 — or not even Ethernet. Either way this check has
                // nothing to say, and the program's parser will decide.
                Some(eth) if eth.ethertype == ETHERTYPE_IPV4 => {
                    Ipv4::parse(frame, ETH_HDR_LEN).is_some()
                }
                _ => true,
            },
        }
    }
}

/// A program's envelope: what runs before it, and what runs after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Applied to every arriving frame.
    pub admit: Admission,
    /// Applied to every frame the program decided to send.
    pub scrub: Scrub,
}

impl Envelope {
    /// The envelope that does nothing at either end.
    pub const IDENTITY: Self = Self {
        admit: Admission::Everything,
        scrub: Scrub::Nothing,
    };

    /// Wrap `inner` so it computes `admit ; inner ; scrub`.
    ///
    /// Returns `inner` unchanged for [`Envelope::IDENTITY`]: composing with the
    /// identity is the identity, and a wrapper whose both halves are no-ops is
    /// a virtual call on the fast path that buys nothing.
    #[must_use]
    pub fn wrap(self, inner: Box<dyn Pipeline>) -> Box<dyn Pipeline> {
        if self == Self::IDENTITY {
            inner
        } else {
            Box::new(Enveloped {
                envelope: self,
                inner,
            })
        }
    }
}

/// A pipeline with an [`Envelope`] around it.
///
/// Delegates its whole control-plane surface: an envelope changes which frames
/// reach the tables and what leaves afterwards, never what the tables are, so
/// `up4ctl` cannot tell a wrapped pipeline from an unwrapped one.
struct Enveloped {
    envelope: Envelope,
    inner: Box<dyn Pipeline>,
}

impl Pipeline for Enveloped {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn engine(&self) -> Box<dyn Engine> {
        Box::new(EnvelopedEngine {
            envelope: self.envelope,
            inner: self.inner.engine(),
        })
    }

    fn tables(&self) -> &dyn TableOps {
        self.inner.tables()
    }
}

/// One shard's view of an [`Enveloped`] pipeline.
struct EnvelopedEngine {
    envelope: Envelope,
    inner: Box<dyn Engine>,
}

impl Engine for EnvelopedEngine {
    #[inline]
    fn process(&mut self, f: &mut FrameCtx<'_>) -> Verdict {
        if !self.envelope.admit.admits(f.frame()) {
            return Verdict::Drop;
        }
        let verdict = self.inner.process(f);
        // Only a frame that is going out: a dropped one is never looked at
        // again, and a punted one goes to the control channel as the pipeline
        // left it.
        if matches!(verdict, Verdict::Forward(_) | Verdict::Broadcast) {
            self.envelope.scrub.apply(f.frame_mut());
        }
        verdict
    }

    fn name(&self) -> &'static str {
        self.inner.name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::{IP_PROTO_UDP, IPV4_MIN_HDR_LEN};

    /// eth(ipv4) + a 20-byte IPv4 header + 8 bytes of payload.
    fn frame() -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR_LEN + IPV4_MIN_HDR_LEN + 8];
        f[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        f[14] = 0x45;
        f[22] = 64;
        f[23] = IP_PROTO_UDP;
        f
    }

    /// The law that lets `up4_catalog::build` leave the `native` backend
    /// unwrapped: over the entire domain the check inspects — all 256 values
    /// of the version/IHL byte — admission and the native parser agree
    /// exactly. Fusion is therefore not an approximation.
    #[test]
    fn fusion_is_sound_for_every_version_and_ihl() {
        let mut f = frame();
        for byte in 0..=u8::MAX {
            f[ETH_HDR_LEN] = byte;
            assert_eq!(
                Admission::CoherentIpv4.admits(&f),
                Ipv4::parse(&f, ETH_HDR_LEN).is_some(),
                "version/ihl byte {byte:#04x}"
            );
        }
    }

    /// The check is about IPv4 and only IPv4: a bridge's traffic goes through.
    #[test]
    fn non_ipv4_frames_are_never_refused_here() {
        let mut f = frame();
        f[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP
        f[ETH_HDR_LEN] = 0xff; // nonsense, were this IPv4
        assert!(Admission::CoherentIpv4.admits(&f));
        assert!(Admission::CoherentIpv4.admits(&[]), "not even Ethernet");
        assert!(
            Admission::CoherentIpv4.admits(&f[..8]),
            "truncated Ethernet"
        );
    }

    /// A truncated IPv4 header is refused for the reason the program would
    /// have refused it anyway — the check never *admits* what P4 rejects.
    #[test]
    fn a_truncated_ipv4_header_is_refused() {
        let f = frame();
        assert!(!Admission::CoherentIpv4.admits(&f[..ETH_HDR_LEN + IPV4_MIN_HDR_LEN - 1]));
    }

    #[test]
    fn everything_admits_everything() {
        assert!(Admission::Everything.admits(&[]));
        assert!(Admission::Everything.admits(&[0xff; 64]));
    }
}
