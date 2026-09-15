import { useState } from 'react';
import type { PowerAction } from '../api/types';
import { Modal } from './Modal';
import { Button, Field } from './ui';

const LABEL: Record<PowerAction, string> = { reboot: 'Reboot', shutdown: 'Shut down', lock: 'Lock', logoff: 'Log off' };

export function PowerDialog({
  action,
  targetLabel,
  onClose,
  onConfirm,
}: {
  action: PowerAction;
  targetLabel: string;
  onClose: () => void;
  onConfirm: (delaySec: number, message: string) => Promise<void>;
}) {
  const [delay, setDelay] = useState(action === 'reboot' || action === 'shutdown' ? 30 : 0);
  const [message, setMessage] = useState(action === 'reboot' ? 'This computer will restart for maintenance.' : action === 'shutdown' ? 'This computer will shut down for maintenance.' : '');
  const [busy, setBusy] = useState(false);
  const delayed = action === 'reboot' || action === 'shutdown';
  return (
    <Modal
      title={`${LABEL[action]} ${targetLabel}`}
      onClose={onClose}
      size="sm"
      center
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="danger"
            solid
            busy={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await onConfirm(delayed ? Math.max(0, delay) : 0, message);
                onClose();
              } finally {
                setBusy(false);
              }
            }}
          >
            {LABEL[action]}
          </Button>
        </>
      }
    >
      <p className="muted">
        {delayed ? `The device will ${action} after the delay. Logged-in users see the message.` : `The interactive session on the device will be ${action === 'lock' ? 'locked' : 'logged off'} immediately.`}
      </p>
      {delayed && (
        <>
          <Field label="Delay (seconds)">
            <input type="number" min={0} max={86400} value={delay} onChange={(e) => setDelay(+e.target.value || 0)} />
          </Field>
          <Field label="Message to users">
            <textarea value={message} onChange={(e) => setMessage(e.target.value)} rows={2} />
          </Field>
        </>
      )}
    </Modal>
  );
}
