import { useState } from 'react';
import { api } from '../api/client';
import type { Group } from '../api/types';
import { errMsg, useToast } from '../state/toast';
import { Modal, useConfirm } from './Modal';
import { Button } from './ui';
import { IconCheck, IconEdit, IconTrash, IconX } from './Icons';

export function GroupsDialog({ groups, onClose, onChanged, canEdit }: { groups: Group[]; onClose: () => void; onChanged: () => void; canEdit: boolean }) {
  const toast = useToast();
  const confirm = useConfirm();
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<number | null>(null);
  const [editName, setEditName] = useState('');

  const create = async () => {
    if (!name.trim()) return;
    setBusy(true);
    try {
      await api.createGroup(name.trim());
      setName('');
      onChanged();
    } catch (err) {
      toast.error('Could not create group', errMsg(err));
    } finally {
      setBusy(false);
    }
  };
  const rename = async (g: Group) => {
    if (!editName.trim() || editName.trim() === g.name) {
      setEditing(null);
      return;
    }
    try {
      await api.updateGroup(g.id, editName.trim(), g.description);
      setEditing(null);
      onChanged();
    } catch (err) {
      toast.error('Rename failed', errMsg(err));
    }
  };
  const remove = async (g: Group) => {
    if (
      !(await confirm({
        title: 'Delete group',
        message: `Delete "${g.name}"? ${g.agent_count ? `${g.agent_count} device(s) will be left without a group.` : ''}`,
        danger: true,
        confirmLabel: 'Delete',
      }))
    )
      return;
    try {
      await api.deleteGroup(g.id);
      onChanged();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  return (
    <Modal title="Device groups" onClose={onClose} size="sm" footer={<Button onClick={onClose}>Done</Button>}>
      {canEdit && (
        <div className="row mb" style={{ flexWrap: 'nowrap' }}>
          <input placeholder="New group name" value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && create()} />
          <Button variant="primary" onClick={create} busy={busy} disabled={!name.trim()}>
            Add
          </Button>
        </div>
      )}
      <div className="card list">
        {groups.map((g) => (
          <div key={g.id} className="list-item">
            {editing === g.id ? (
              <>
                <input value={editName} autoFocus onChange={(e) => setEditName(e.target.value)} onKeyDown={(e) => (e.key === 'Enter' ? rename(g) : e.key === 'Escape' ? setEditing(null) : null)} />
                <Button size="sm" icon variant="ghost" onClick={() => rename(g)} aria-label="Save">
                  <IconCheck />
                </Button>
                <Button size="sm" icon variant="ghost" onClick={() => setEditing(null)} aria-label="Cancel">
                  <IconX />
                </Button>
              </>
            ) : (
              <>
                <div className="grow">
                  <div className="title">{g.name}</div>
                  <div className="sub">
                    {g.agent_count} device{g.agent_count === 1 ? '' : 's'}
                  </div>
                </div>
                {canEdit && (
                  <>
                    <Button
                      size="sm"
                      icon
                      variant="ghost"
                      aria-label="Rename"
                      onClick={() => {
                        setEditing(g.id);
                        setEditName(g.name);
                      }}
                    >
                      <IconEdit />
                    </Button>
                    <Button size="sm" icon variant="ghost" aria-label="Delete" onClick={() => remove(g)}>
                      <IconTrash />
                    </Button>
                  </>
                )}
              </>
            )}
          </div>
        ))}
        {!groups.length && <div className="empty">No groups yet.</div>}
      </div>
    </Modal>
  );
}
