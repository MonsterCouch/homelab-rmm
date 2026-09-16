import { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import { CopyButton } from './ui';
import '../styles/mobile-pages.css';

/**
 * The out-of-band pairing channel for the Android app (docs/ANDROID.md §5.5).
 *
 * The pin is never fetched over the connection it secures, so the console
 * publishes it two ways a phone can consume without trusting the network:
 * a QR read screen-to-camera, and the same URI as text to copy into a note or
 * a password manager. Both carry the identical string; neither adds a
 * dependency (qrcode is already used by Account.tsx) and neither asks the
 * server for anything new.
 *
 * Nothing is rendered when the value could not be pinned: the app refuses an
 * http:// URL in release and a fingerprint that is not 64 hex characters, so
 * emitting such a URI would only produce a scan that dead-ends on the phone.
 */

/** Matches internal/agent/conn.go:25 and Fingerprint.normalize in :trust. */
export function normalizeFingerprint(s: string): string {
  return s.replace(/:/g, '').replace(/\s+/g, '').toLowerCase();
}

export function isFingerprint(s: string): boolean {
  return /^[0-9a-f]{64}$/.test(s);
}

/** homelabrmm://pair?url=<enc>&fp=<64hex>&name=<label> */
export function pairUri(url: string, fingerprint: string, name: string): string {
  return `homelabrmm://pair?url=${encodeURIComponent(url)}&fp=${normalizeFingerprint(fingerprint)}&name=${encodeURIComponent(name)}`;
}

/** The host of the public URL is the most useful default label on the phone. */
function defaultName(url: string): string {
  try {
    return new URL(url).hostname || 'Homelab RMM';
  } catch {
    return 'Homelab RMM';
  }
}

export function PairCard({ url, fingerprint, name }: { url: string; fingerprint: string; name?: string }) {
  const fp = normalizeFingerprint(fingerprint ?? '');
  const httpsUrl = /^https:\/\//i.test(url ?? '');
  const ok = !!url && httpsUrl && isFingerprint(fp);
  const uri = ok ? pairUri(url, fp, name || defaultName(url)) : '';
  const [qr, setQr] = useState<string | null>(null);
  const [qrError, setQrError] = useState<string | null>(null);

  useEffect(() => {
    if (!uri) {
      setQr(null);
      return;
    }
    let live = true;
    setQrError(null);
    // Rendered at 2x the display box so it stays sharp on a phone camera, and
    // always black on white so a dark console theme cannot invert it.
    QRCode.toDataURL(uri, { width: 464, margin: 2, errorCorrectionLevel: 'M', color: { dark: '#000000', light: '#ffffff' } })
      .then((d) => live && setQr(d))
      .catch((err) => live && setQrError(err instanceof Error ? err.message : String(err)));
    return () => {
      live = false;
    };
  }, [uri]);

  if (!ok) {
    return (
      <p className="muted small" style={{ margin: 0 }}>
        {!url
          ? 'Set the public URL above before pairing a phone.'
          : !httpsUrl
            ? `The Android app refuses a plain-http server, and ${url} is not https. Pair once this server is reachable over TLS.`
            : 'This server reports no certificate fingerprint (it is running with --insecure or terminating TLS elsewhere), so there is nothing for the phone to pin.'}
      </p>
    );
  }

  return (
    <div className="pair">
      {qr && <img className="pair-qr" src={qr} alt="Pairing QR code" width={232} height={232} />}
      <div className="pair-body">
        <p className="muted small" style={{ margin: 0 }}>
          Scan this from <b>Add server</b> in the Homelab RMM Android app, or copy the link below. The fingerprint travels screen-to-camera and is confirmed by
          hand on the phone — it is never fetched over the connection it secures.
        </p>
        {qrError && <p className="muted small" style={{ margin: 0 }}>The QR image could not be drawn ({qrError}); the link below carries the same value.</p>}
        <div className="code-block pair-uri">
          {uri}
          <span className="copy">
            <CopyButton text={uri} />
          </span>
        </div>
      </div>
    </div>
  );
}
