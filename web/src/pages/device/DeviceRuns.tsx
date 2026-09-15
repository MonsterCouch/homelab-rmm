import { useState } from 'react';
import { api } from '../../api/client';
import { RunDrawer } from '../../components/RunDrawer';
import { RunsTable } from '../../components/RunsTable';
import { ErrorBox } from '../../components/ui';
import { useAsync } from '../../hooks/useAsync';
import { useLiveReload } from '../../hooks/useEvents';
import type { TabProps } from './DeviceDetail';

export function DeviceRuns({ agent }: TabProps) {
  const runs = useAsync(() => api.runs(agent.id, 300), [agent.id]);
  useLiveReload(['run'], runs.reload, { agentId: agent.id, debounceMs: 700 });
  const [open, setOpen] = useState<string | null>(null);
  return (
    <>
      {runs.error && <ErrorBox error={runs.error} onRetry={runs.reload} />}
      <RunsTable rows={runs.data} loading={runs.loading} onOpen={(r) => setOpen(r.id)} showDevice={false} emptyTitle="No scripts have run on this device" />
      {open && <RunDrawer runId={open} onClose={() => setOpen(null)} onChanged={runs.reload} onOpenRun={setOpen} />}
    </>
  );
}
