// The viewer half of the terminal's WebRTC byte path (docs/TERMINAL-PROTOCOL.md).
// The agent answers; signalling rides the terminal WebSocket, so this module
// only builds JSON and never touches a socket itself — the caller hands in
// `sendSignal`.
//
// One ordered data channel labelled "term": a binary message is raw pty bytes
// in both directions, a text message is a JSON control frame
// ({t:'resize',cols,rows} or {t:'close'}).
//
// Lifecycle: construct -> start() (offer goes out) -> applyAnswer() /
// addCandidate() as the agent replies -> close(). close() is idempotent and
// detaches every handler first, so a late event from a dying connection can
// never reach the page.

export type TermRtcState = 'new' | 'connecting' | 'connected' | 'disconnected' | 'failed' | 'closed';

export interface TermRtcHandlers {
  /** The data channel opened. */
  onOpen: () => void;
  /** Raw pty bytes from the shell. */
  onData: (data: Uint8Array) => void;
  /** The connection state changed (deduplicated). */
  onState: (state: TermRtcState) => void;
}

const CHANNEL = 'term';
/** Input and control are small; this just keeps one paste from ever exceeding a message. */
const MAX_SEND = 32 * 1024;

/** Older browsers lack connectionState; the ICE state is the nearest stand-in. */
function stateOf(pc: RTCPeerConnection): TermRtcState {
  if (pc.connectionState) return pc.connectionState as TermRtcState;
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

export class TerminalRTC {
  private pc: RTCPeerConnection | null;
  private channel: RTCDataChannel | null;
  private handlers: TermRtcHandlers | null;
  private state: TermRtcState = 'new';
  /** Candidates that beat the answer here; addIceCandidate would reject them. */
  private pending: RTCIceCandidateInit[] = [];
  private haveAnswer = false;
  private readonly enc = new TextEncoder();

  constructor(
    iceServers: RTCIceServer[],
    private sendSignal: (msg: Record<string, unknown>) => void,
    handlers: TermRtcHandlers,
  ) {
    this.handlers = handlers;
    const pc = new RTCPeerConnection({ iceServers });
    this.pc = pc;
    const ch = pc.createDataChannel(CHANNEL, { ordered: true });
    ch.binaryType = 'arraybuffer';
    this.channel = ch;
    ch.onopen = () => this.handlers?.onOpen();
    ch.onmessage = (e: MessageEvent) => {
      if (e.data instanceof ArrayBuffer) this.handlers?.onData(new Uint8Array(e.data));
    };
    ch.onclose = () => {
      // A channel that closes under a live connection ends the transport.
      const h = this.handlers;
      if (h && this.state !== 'closed' && this.state !== 'failed') {
        this.state = 'closed';
        h.onState('closed');
      }
    };
    pc.onicecandidate = (e) => {
      if (e.candidate) this.sendSignal({ t: 'rtc_candidate', candidate: e.candidate.toJSON() });
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

  /** The channel is open and can carry bytes. */
  get open(): boolean {
    return this.channel?.readyState === 'open';
  }

  /** Create the offer and send it. Rejects if the browser cannot build one. */
  async start(): Promise<void> {
    const pc = this.pc;
    if (!pc) return;
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    if (!this.pc) return; // closed while the offer was being made
    this.sendSignal({ t: 'rtc_offer', sdp: offer.sdp });
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

  /** Send keystrokes as raw bytes. Returns false when the channel is not open. */
  sendBytes(data: string | Uint8Array): boolean {
    const ch = this.channel;
    if (!ch || ch.readyState !== 'open') return false;
    const bytes = typeof data === 'string' ? this.enc.encode(data) : data;
    try {
      for (let i = 0; i < bytes.length; i += MAX_SEND) {
        // slice() copies, so the message owns a plain ArrayBuffer.
        ch.send(bytes.slice(i, i + MAX_SEND));
      }
      return true;
    } catch {
      return false; // the channel closed under us; the WebSocket path takes over
    }
  }

  /** Send a JSON control frame. Returns false when the channel is not open. */
  sendControl(msg: { t: 'resize'; cols: number; rows: number } | { t: 'close' }): boolean {
    const ch = this.channel;
    if (!ch || ch.readyState !== 'open') return false;
    try {
      ch.send(JSON.stringify(msg));
      return true;
    } catch {
      return false;
    }
  }

  close(): void {
    const pc = this.pc;
    if (!pc) return;
    this.pc = null;
    this.handlers = null;
    pc.onicecandidate = null;
    pc.onconnectionstatechange = null;
    pc.oniceconnectionstatechange = null;
    const ch = this.channel;
    this.channel = null;
    if (ch) {
      ch.onopen = null;
      ch.onclose = null;
      ch.onmessage = null;
      ch.close();
    }
    this.pending = [];
    this.state = 'closed';
    pc.close();
  }
}
