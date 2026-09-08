import { useState, useEffect } from 'react';
import { StickyNote } from 'lucide-react';
import { API_BASE, authHeaders } from '../../config';
import DrawerShell from '../ui/DrawerShell';
import { TYPOGRAPHY } from '../../theme/typography';
import { useInvestigationUI } from '../../context/InvestigationUIContext';

export default function AnalystNotesPanel({ sha256 }: { sha256: string }) {
  const [isOpen, setIsOpen] = useState(false);
  const { closeAllDrawers } = useInvestigationUI();
  const [notes, setNotes] = useState('');
  const [savedNotes, setSavedNotes] = useState<Array<{ id: number; text: string; author: string; created_at: string }>>([]);
  const [loading, setLoading] = useState(false);

  const fetchNotes = async () => {
    try {
      const res = await fetch(`${API_BASE}/cases/${sha256}/notes`, { headers: authHeaders() });
      if (res.ok) {
        const data = await res.json();
        setSavedNotes(data.notes || []);
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    if (isOpen) fetchNotes();
  }, [isOpen, sha256]);

  const save = async () => {
    if (!notes.trim()) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/cases/${sha256}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ text: notes }),
      });
      if (res.ok) {
        setNotes('');
        await fetchNotes();
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <button
        type="button"
        onClick={() => {
          // Notes and the case drawers share a z-index, so opening one over the
          // other would put two modal surfaces on screen with two focus traps
          // fighting for the same Tab key.
          closeAllDrawers();
          setIsOpen(true);
        }}
        className="fixed bottom-6 right-6 z-40 flex items-center gap-2 px-4 py-3 bg-slate-900 text-white text-xs font-semibold rounded-full shadow-xl border border-slate-700"
      >
        <StickyNote className="h-4 w-4 text-blue-400" />
        Analyst notes
        {savedNotes.length > 0 && (
          <span className="w-5 h-5 rounded-full bg-blue-600 text-[13px] flex items-center justify-center">
            {savedNotes.length}
          </span>
        )}
      </button>
      <DrawerShell
        open={isOpen}
        onClose={() => setIsOpen(false)}
        title="Analyst notes"
        labelledById="analyst-notes-title"
        subtitle={
          savedNotes.length > 0
            ? `${savedNotes.length} note${savedNotes.length === 1 ? '' : 's'} on this case`
            : 'No notes recorded yet'
        }
      >
        <div className="space-y-4">
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            className="w-full border border-slate-300 rounded-md p-2.5 text-sm min-h-[100px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            placeholder="Investigation notes…"
            aria-label="Investigation notes"
          />
          <button
            type="button"
            disabled={loading}
            onClick={save}
            className={`w-full py-2 ${TYPOGRAPHY.button} bg-blue-700 hover:bg-blue-800 text-white`}
          >
            Save note
          </button>
          {savedNotes.map((n) => (
            <div key={n.id} className="p-3 bg-white border border-slate-200 rounded-md">
              <div className={TYPOGRAPHY.caption}>
                {n.author} &middot; {n.created_at}
              </div>
              <div className={`${TYPOGRAPHY.bodySmall} mt-1 text-slate-800`}>{n.text}</div>
            </div>
          ))}
        </div>
      </DrawerShell>
    </>
  );
}
