// The viewer half of the remote-desktop WebRTC transport. The desktop helper
// answers; signalling rides the same WebSocket the JPEG tiles use (the server
// bridges it verbatim), so this module only builds JSON and never touches a
// socket itself — the caller hands in `sendSignal`.
//
// Lifecycle: construct -> start() (offer goes out) -> applyAnswer() /
// addCandidate() as the helper replies -> close(). close() is idempotent and
// detaches every handler first, so a late event from a dying connection can
// never reach the page.

export type RtcState = 'new' | 'connecting' | 'connected' | 'disconnected' | 'failed' | 'closed';

export interface RtcHandlers {
  /** The helper's video arrived; hand it to a <video>. */
  onStream: (stream: MediaStream) => void;
  /** The connection state changed (deduplicated). */
  onState: (state: RtcState) => void;
}

export interface RtcStats {
  /** Round-trip time of the selected candidate pair, or null if unknown. */
  rttMs: number | null;
  /** Decoded frames per second, as the browser reports it. */
  fps: number;
  /** Video bytes received per second since the previous call. */
  bytesPerSec: number;
}

/** Carries mousemove only: a stale position is worthless, so never retransmit. */
const CH_UNRELIABLE = 'input-unreliable';
/** Everything else: clicks and keys must arrive, and in order. */
const CH_RELIABLE = 'input-reliable';

/** Older browsers lack connectionState; the ICE state is the nearest stand-in. */
function stateOf(pc: RTCPeerConnection): RtcState {
  if (pc.connectionState) return pc.connectionState as RtcState;
  switch (pc.iceConnectionState) {
    case 'connected':
    case 'completed':
      return 'connected';
    case 'disconnected':
      return 'disconnected';
    case 'failed':
      return 'failed';
    case 'closed':
      return 'closed';
    case 'checking':
      return 'connecting';
    default:
      return 'new';
  }
}

export class ViewerRTC {
  private pc: RTCPeerConnection | null;
  private unreliable: RTCDataChannel | null = null;
  private reliable: RTCDataChannel | null = null;
  private handlers: RtcHandlers | null;
  private state: RtcState = 'new';
  /** Candidates that beat the answer here; addIceCandidate would reject them. */
  private pending: RTCIceCandidateInit[] = [];
  private haveAnswer = false;
  private lastBytes = 0;
  private lastAt = 0;

  constructor(
    iceServers: RTCIceServer[],
    private sendSignal: (msg: Record<string, unknown>) => void,
    handlers: RtcHandlers,
  ) {
    this.handlers = handlers;
    const pc = new RTCPeerConnection({ iceServers });
    this.pc = pc;
    pc.addTransceiver('video', { direction: 'recvonly' });
    this.unreliable = pc.createDataChannel(CH_UNRELIABLE, { ordered: false, maxRetransmits: 0 });
    this.reliable = pc.createDataChannel(CH_RELIABLE, { ordered: true });
    pc.ontrack = (e) => {
      const stream = e.streams[0] ?? new MediaStream([e.track]);
      this.handlers?.onStream(stream);
    };
    pc.onicecandidate = (e) => {
      if (e.candidate) this.sendSignal({ t: 'webrtc_candidate', candidate: e.candidate.toJSON() });
    };
    const changed = () => {
      if (!this.pc) return;
      const next = stateOf(this.pc);
      if (next === this.state) return;
      this.state = next;
      this.handlers?.onState(next);
    };
    pc.onconnectionstatechange = changed;
    pc.oniceconnectionstatechange = changed;
  }

  get connected(): boolean {
    return this.state === 'connected';
  }

  /** Create the offer and send it. Rejects if the browser cannot build one. */
  async start(): Promise<void> {
    const pc = this.pc;
    if (!pc) return;
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    if (!this.pc) return; // closed while the offer was being made
    this.sendSignal({ t: 'webrtc_offer', sdp: offer.sdp });
  }

  async applyAnswer(sdp: string): Promise<void> {
    const pc = this.pc;
    if (!pc) return;
    await pc.setRemoteDescription({ type: 'answer', sdp });
    this.haveAnswer = true;
    const queued = this.pending;
    this.pending = [];
    for (const c of queued) await this.addCandidate(c);
  }

  async addCandidate(init: RTCIceCandidateInit): Promise<void> {
    const pc = this.pc;
    if (!pc) return;
    if (!this.haveAnswer) {
      this.pending.push(init);
      return;
    }
    try {
      await pc.addIceCandidate(init);
    } catch (err) {
      // A stray candidate is not worth the session; ICE will use the others.
      console.warn('addIceCandidate failed', err);
    }
  }

  /**
   * Send one input message over a data channel. Returns false when no channel
   * is open, so the caller can use the WebSocket instead.
   */
  sendInput(msg: Record<string, unknown>): boolean {
    const json = JSON.stringify(msg);
    try {
      if (msg.t === 'mousemove' && this.unreliable?.readyState === 'open') {
        this.unreliable.send(json);
        return true;
      }
      if (this.reliable?.readyState === 'open') {
        this.reliable.send(json);
        return true;
      }
    } catch {
      /* the channel closed under us; the WebSocket path takes over */
    }
    return false;
  }

  /** Numbers for the diagnostics HUD. Resolves to zeros if the pc is gone. */
  async getStats(): Promise<RtcStats> {
    const out: RtcStats = { rttMs: null, fps: 0, bytesPerSec: 0 };
    const pc = this.pc;
    if (!pc) return out;
    const report = await pc.getStats();
    let selectedId: string | undefined;
    let bytesReceived = 0;
    report.forEach((r) => {
      if (r.type === 'transport' && r.selectedCandidatePairId) selectedId = r.selectedCandidatePairId as string;
    });
    report.forEach((r) => {
      if (r.type === 'inbound-rtp' && (r.kind ?? r.mediaType) === 'video') {
        out.fps = Math.round((r.framesPerSecond as number | undefined) ?? 0);
        bytesReceived = (r.bytesReceived as number | undefined) ?? 0;
      } else if (r.type === 'candidate-pair') {
        // Firefox has no selectedCandidatePairId; its pair says `selected`.
        const chosen = selectedId ? r.id === selectedId : r.nominated === true && r.state === 'succeeded';
        const rtt = r.currentRoundTripTime as number | undefined;
        if (chosen && typeof rtt === 'number') out.rttMs = Math.round(rtt * 1000);
      }
    });
    const now = performance.now();
    if (this.lastAt && now > this.lastAt && bytesReceived >= this.lastBytes) {
      out.bytesPerSec = ((bytesReceived - this.lastBytes) * 1000) / (now - this.lastAt);
    }
    this.lastBytes = bytesReceived;
    this.lastAt = now;
    return out;
  }

  close(): void {
    const pc = this.pc;
    if (!pc) return;
    this.pc = null;
    this.handlers = null;
    pc.ontrack = null;
    pc.onicecandidate = null;
    pc.onconnectionstatechange = null;
    pc.oniceconnectionstatechange = null;
    for (const ch of [this.unreliable, this.reliable]) {
      if (!ch) continue;
      ch.onopen = null;
      ch.onclose = null;
      ch.onmessage = null;
      ch.close();
    }
    this.unreliable = null;
    this.reliable = null;
    this.pending = [];
    this.state = 'closed';
    pc.close();
  }
}
