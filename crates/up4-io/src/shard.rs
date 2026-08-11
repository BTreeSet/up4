//! The datapath (spec S6.2, S6.3).
//!
//! One shard owns one socket, one engine instance, and every buffer it will
//! ever use. A frame is received, processed, and sent on the same thread and
//! is copied exactly once — from the receive arena into its destination's
//! staging buffer, which is also the buffer it is sent from.
//!
//! ## The headroom invariant
//!
//! A GRO read lands many segments back to back in one slot, so a segment's
//! "space in front of it" is whatever precedes it in that slot. The arena
//! reserves [`HEADROOM`] bytes before the first segment, and segments are
//! processed front to back — each is copied out to staging before the next is
//! touched. So when segment *k* is handed to the pipeline, everything before it
//! is dead space it may write into, and the guarantee spec S7.1 asks for
//! (at least 64 bytes) holds for every segment, not just the first, with no
//! scratch buffer and no second copy.
//!
//! ## Cost
//!
//! Per read: one `recvmmsg`. Per segment: one O(1) header decode, one O(1)
//! demux (done once per read, not per segment), one engine call, one copy into
//! staging. Per batch: one `sendmsg` per destination per GSO run. No allocation
//! anywhere in the loop — the arena, the staging buffers, and the per-vport
//! state are all sized once at startup.

use crate::{
    clock,
    punt::PuntQueue,
    socket::{FabricSocket, HEADROOM, RX_BATCH, is_transient},
    tx::TxQueue,
    warn::WarnRate,
};
use quinn_udp::{RecvMeta, Transmit};
use std::{io, sync::Arc};
use tracing::warn;
use up4_config::{VportIdx, VportTable};
use up4_engine::{Engine, FrameCtx, Verdict};
use up4_metrics::{Counter, Hist, Metrics, VportCounter};
use up4_wire::{Hdr, OVERLAY_HDR_LEN, Seq, SeqEvent, SeqTracker};

use crate::signal::Stop;

/// What a shard needs besides its socket and its engine.
#[derive(Clone)]
pub struct ShardParams {
    /// Shard index, for log context.
    pub id: usize,
    /// The topology, read-only after startup.
    pub topology: Arc<VportTable>,
    /// The counter registry, shared with every other shard.
    pub metrics: Arc<Metrics>,
    /// Largest inner frame this fabric carries.
    pub inner_mtu: usize,
    /// The punt queue, when `[punt]` is configured.
    pub punt: Option<Arc<PuntQueue>>,
}

/// One rate limiter per condition class (spec S12).
#[derive(Debug, Default)]
struct Warnings {
    unknown_peer: WarnRate,
    bad_header: WarnRate,
    oversize: WarnRate,
    unknown_port: WarnRate,
    would_block: WarnRate,
    send_error: WarnRate,
    punt_overflow: WarnRate,
    punt_unconfigured: WarnRate,
}

/// A receive/transmit shard.
pub struct Shard {
    id: usize,
    socket: FabricSocket,
    engine: Box<dyn Engine>,
    topology: Arc<VportTable>,
    metrics: Arc<Metrics>,
    punt: Option<Arc<PuntQueue>>,
    inner_mtu: usize,
    /// Per destination vport, indexed by [`VportIdx`].
    tx: Box<[TxQueue]>,
    rx_seq: Box<[SeqTracker]>,
    tx_seq: Box<[Seq]>,
    /// Every vport index, so broadcast fan-out allocates nothing.
    fanout: Box<[VportIdx]>,
    warn: Warnings,
}

impl Shard {
    /// Assemble a shard around an already-bound socket and a fresh engine.
    #[must_use]
    pub fn new(socket: FabricSocket, engine: Box<dyn Engine>, params: ShardParams) -> Self {
        let n = params.topology.len();
        Self {
            id: params.id,
            socket,
            engine,
            metrics: params.metrics,
            punt: params.punt,
            inner_mtu: params.inner_mtu,
            tx: (0..n).map(|_| TxQueue::new(params.inner_mtu)).collect(),
            rx_seq: (0..n).map(|_| SeqTracker::new()).collect(),
            tx_seq: (0..n).map(|_| Seq::new(0)).collect(),
            fanout: params.topology.iter().map(|(idx, _)| idx).collect(),
            topology: params.topology,
            warn: Warnings::default(),
        }
    }

    /// Bytes each receive slot must hold: a fully coalesced GRO read, plus the
    /// headroom the pipeline is promised.
    #[must_use]
    pub fn slot_len(&self) -> usize {
        HEADROOM + (OVERLAY_HDR_LEN + self.inner_mtu) * self.socket.caps().gro_segments.max(1)
    }

    /// Run until `stop` is requested, then flush what is staged.
    ///
    /// Returns `Err` only for a socket failure that is not transient; a
    /// receive timeout is the loop's heartbeat, not an error.
    pub fn run(&mut self, stop: &Stop) -> io::Result<()> {
        let mut arena = RxArena::new(RX_BATCH, self.slot_len());
        let mut metas = [RecvMeta::default(); RX_BATCH];

        while !stop.requested() {
            let received = match arena.recv(&self.socket, &mut metas) {
                Ok(n) => n,
                Err(e) if is_transient(&e) => continue,
                Err(e) => return Err(e),
            };
            self.metrics.bump(Counter::SyscallsRx);
            // One clock read per batch, not per frame: the overlay timestamp
            // measures milliseconds-scale one-way delay, not intra-batch skew.
            let now = clock::now_us();
            for (slot, meta) in arena.slots_mut().zip(metas.iter()).take(received) {
                self.receive(slot, *meta, now);
            }
            self.flush_all();
        }
        self.flush_all();
        Ok(())
    }

    /// Process one received buffer, which GRO may have filled with many
    /// segments (spec S6.2 steps 2-7).
    fn receive(&mut self, slot: &mut [u8], meta: RecvMeta, now: u32) {
        if meta.len == 0 {
            return;
        }
        // A read without GRO reports no stride; the whole buffer is one segment.
        let stride = if meta.stride == 0 {
            meta.len
        } else {
            meta.stride
        };
        let segments = meta.len.div_ceil(stride);
        self.metrics.hist(Hist::GroSegmentsPerRead).record(segments);

        // Demux once per read: every segment in it shares a source tuple.
        let Some(ingress) = self.topology.idx_of_peer(&meta.addr) else {
            self.metrics.add(Counter::RxUnknownPeer, segments as u64);
            if let Some(count) = self.warn.unknown_peer.tick() {
                warn!(shard = self.id, peer = %meta.addr, count, "frames from an unconfigured peer");
            }
            return;
        };
        let ingress_id = self.topology.get(ingress).id.get();
        let payload_end = HEADROOM + meta.len;

        for k in 0..segments {
            let seg_start = HEADROOM + k * stride;
            let seg_end = payload_end.min(seg_start + stride);

            let hdr = match up4_wire::decode(&slot[seg_start..seg_end]) {
                Ok(hdr) => hdr,
                Err(e) => {
                    self.metrics.bump(Counter::RxBadHeader);
                    if let Some(count) = self.warn.bad_header.tick() {
                        warn!(shard = self.id, peer = %meta.addr, count, "{e}");
                    }
                    continue;
                }
            };
            let frame_start = seg_start + OVERLAY_HDR_LEN;
            let frame_len = seg_end - frame_start;

            let event = self.rx_seq[ingress.get()].observe(hdr.seq);
            let block = self.metrics.vport(ingress);
            block.bump(VportCounter::RxPkts);
            block.add(VportCounter::RxBytes, frame_len as u64);
            match event {
                SeqEvent::InOrder => {}
                SeqEvent::Gap(missing) => {
                    block.add(VportCounter::RxSeqGapTotal, u64::from(missing));
                }
                SeqEvent::Reorder => block.bump(VportCounter::RxReorder),
            }

            let (verdict, head, len) = {
                // Everything before `frame_start` in this slot has already been
                // copied out (see the headroom invariant above), so the
                // pipeline may encapsulate into it.
                let Some(mut ctx) = FrameCtx::new(
                    &mut slot[..seg_end],
                    frame_start,
                    frame_len,
                    ingress_id,
                    now,
                ) else {
                    continue;
                };
                let verdict = self.engine.process(&mut ctx);
                (verdict, ctx.headroom(), ctx.len())
            };

            if verdict != Verdict::Drop && len > self.inner_mtu {
                self.metrics.bump(Counter::TxOversizeDrop);
                if let Some(count) = self.warn.oversize.tick() {
                    warn!(
                        shard = self.id,
                        len,
                        mtu = self.inner_mtu,
                        count,
                        "frame exceeds inner MTU"
                    );
                }
                continue;
            }
            self.dispatch(verdict, &slot[head..head + len], ingress, ingress_id, now);
        }
    }

    /// Route a verdict to its one destination (spec S6.3).
    fn dispatch(
        &mut self,
        verdict: Verdict,
        frame: &[u8],
        ingress: VportIdx,
        ingress_id: u16,
        now: u32,
    ) {
        match verdict {
            Verdict::Drop => self.metrics.bump(Counter::EngineDrop),
            Verdict::Punt => match &self.punt {
                Some(queue) => {
                    if !queue.push(frame, ingress_id, now) {
                        self.metrics.bump(Counter::PuntOverflowDrop);
                        if let Some(count) = self.warn.punt_overflow.tick() {
                            warn!(shard = self.id, count, "punt queue full");
                        }
                    }
                }
                None => {
                    self.metrics.bump(Counter::PuntUnconfiguredDrop);
                    if let Some(count) = self.warn.punt_unconfigured.tick() {
                        warn!(
                            shard = self.id,
                            count, "punt verdict with no [punt] configured"
                        );
                    }
                }
            },
            Verdict::Forward(port) => match self.topology.idx_of_id(port) {
                Some(egress) => self.stage(egress, frame, ingress_id, now),
                None => {
                    self.metrics.bump(Counter::TxUnknownPort);
                    if let Some(count) = self.warn.unknown_port.tick() {
                        warn!(
                            shard = self.id,
                            port, count, "pipeline forwarded to an unconfigured vport"
                        );
                    }
                }
            },
            Verdict::Broadcast => {
                self.metrics.vport(ingress).bump(VportCounter::TxBroadcast);
                // Indexed rather than iterated: `stage` needs `&mut self`.
                for i in 0..self.fanout.len() {
                    let egress = self.fanout[i];
                    if egress != ingress {
                        self.stage(egress, frame, ingress_id, now);
                    }
                }
            }
        }
    }

    /// Stamp an overlay header and stage the frame for `egress`.
    fn stage(&mut self, egress: VportIdx, frame: &[u8], ingress_id: u16, now: u32) {
        if self.tx[egress.get()].is_full() {
            self.flush(egress);
        }
        let seq = self.tx_seq[egress.get()];
        let mut hdr = [0u8; OVERLAY_HDR_LEN];
        up4_wire::encode(
            &Hdr {
                ingress_vport: ingress_id,
                seq,
                ts_us: now,
            },
            &mut hdr,
        );

        if self.tx[egress.get()].push(&hdr, frame) {
            self.tx_seq[egress.get()] = seq.next();
        } else {
            // Unreachable: the queue was just flushed if full, and oversize
            // frames were rejected before dispatch. Counted, not asserted.
            self.metrics.bump(Counter::TxOversizeDrop);
        }
    }

    /// Flush every nonempty staging queue.
    fn flush_all(&mut self) {
        for i in 0..self.fanout.len() {
            let idx = self.fanout[i];
            if !self.tx[idx.get()].is_empty() {
                self.flush(idx);
            }
        }
    }

    /// Send one destination's staged segments and clear the queue.
    fn flush(&mut self, egress: VportIdx) {
        let queue = &self.tx[egress.get()];
        if queue.is_empty() {
            return;
        }
        let destination = self.topology.get(egress).peer;
        let segments = queue.len();
        let inner_bytes = queue.inner_bytes();
        self.metrics.hist(Hist::TxBatchSize).record(segments);

        let mut sent = 0;
        for run in queue.runs(self.socket.caps().max_gso_segments) {
            let transmit = Transmit {
                destination,
                ecn: None,
                contents: &queue.bytes()[run.start..run.end],
                // Advertising a segment size for a single datagram makes some
                // drivers unhappy; quinn-udp also normalizes this, and being
                // explicit here keeps the intent readable.
                segment_size: (run.count > 1).then_some(run.segment_size),
                src_ip: None,
            };
            if self.send(&transmit) {
                sent += run.count;
            }
        }

        let block = self.metrics.vport(egress);
        block.add(VportCounter::TxPkts, sent as u64);
        if sent == segments {
            block.add(VportCounter::TxBytes, inner_bytes as u64);
        } else {
            // Partial success: charge only what left, by segment share.
            block.add(
                VportCounter::TxBytes,
                (inner_bytes * sent / segments.max(1)) as u64,
            );
        }
        self.tx[egress.get()].clear();
    }

    /// Send one transmit, retrying a would-block exactly once (spec S6.3).
    ///
    /// Blocking sockets make would-block rare; busy-looping on it would turn a
    /// transient stall into a spin, so the second failure drops the remainder
    /// and says so.
    fn send(&self, transmit: &Transmit<'_>) -> bool {
        match self.socket.send(transmit) {
            Ok(()) => {
                self.metrics.bump(Counter::SyscallsTx);
                true
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => match self.socket.send(transmit) {
                Ok(()) => {
                    self.metrics.bump(Counter::SyscallsTx);
                    true
                }
                Err(_) => {
                    self.metrics.bump(Counter::TxWouldBlock);
                    if let Some(count) = self.warn.would_block.tick() {
                        warn!(
                            shard = self.id,
                            count, "send would block twice; remainder dropped"
                        );
                    }
                    false
                }
            },
            Err(e) => {
                self.metrics.bump(Counter::TxSendError);
                if let Some(count) = self.warn.send_error.tick() {
                    warn!(shard = self.id, count, dest = %transmit.destination, "send failed: {e}");
                }
                false
            }
        }
    }
}

/// The receive arena: `slots` fixed-size buffers, allocated once.
#[derive(Debug)]
pub struct RxArena {
    buf: Box<[u8]>,
    slot_len: usize,
}

impl RxArena {
    /// Allocate `slots` buffers of `slot_len` bytes each.
    #[must_use]
    pub fn new(slots: usize, slot_len: usize) -> Self {
        Self {
            buf: vec![0u8; slots * slot_len].into_boxed_slice(),
            slot_len,
        }
    }

    /// Receive into the arena, leaving [`HEADROOM`] free in front of each slot.
    ///
    /// The `IoSliceMut` array is rebuilt per call because it borrows the arena;
    /// it lives on the stack and costs a handful of pointer writes, not an
    /// allocation.
    pub fn recv(&mut self, socket: &FabricSocket, metas: &mut [RecvMeta]) -> io::Result<usize> {
        let mut chunks = self.buf.chunks_exact_mut(self.slot_len);
        let mut iovs: [io::IoSliceMut<'_>; RX_BATCH] = std::array::from_fn(|_| {
            // The arena was sized `RX_BATCH * slot_len`, so there are exactly
            // this many chunks and `from_fn` asks for exactly this many.
            let chunk = chunks.next().expect("arena holds RX_BATCH slots");
            io::IoSliceMut::new(&mut chunk[HEADROOM..])
        });
        socket.recv(&mut iovs, metas)
    }

    /// The slots, including their headroom.
    pub fn slots_mut(&mut self) -> impl Iterator<Item = &mut [u8]> {
        self.buf.chunks_exact_mut(self.slot_len)
    }
}
