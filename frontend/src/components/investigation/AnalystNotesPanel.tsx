import { useState, useEffect } from 'react';
import { StickyNote, X } from 'lucide-react';
import { API_BASE, authHeaders } from '../../config';

export default function AnalystNotesPanel({ sha256 }: { sha256: string }) {
  const [isOpen, setIsOpen] = useState(false);
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
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 z-40 flex items-center gap-2 px-4 py-3 bg-slate-900 text-white text-xs font-semibold rounded-full shadow-xl border border-slate-700"
      >
        <StickyNote className="h-4 w-4 text-blue-400" />
        Analyst notes
        {savedNotes.length > 0 && (
          <span className="w-5 h-5 rounded-full bg-blue-600 text-[10px] flex items-center justify-center">
            {savedNotes.length}
          </span>
        )}
      </button>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex justify-end">
          <div className="absolute inset-0 bg-slate-900/40" onClick={() => setIsOpen(false)} />
          <div className="relative w-96 bg-white h-full shadow-2xl border-l flex flex-col">
            <div className="px-5 py-4 border-b flex justify-between items-center">
              <h3 className="text-sm font-bold">Analyst notes</h3>
              <button type="button" onClick={() => setIsOpen(false)}><X className="h-4 w-4" /></button>
            </div>
            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                className="w-full border rounded-lg p-2 text-sm min-h-[100px]"
                placeholder="Investigation notes…"
              />
              <button
                type="button"
                disabled={loading}
                onClick={save}
                className="w-full py-2 bg-blue-700 text-white text-xs font-semibold rounded-lg"
              >
                Save note
              </button>
              {savedNotes.map((n) => (
                <div key={n.id} className="p-3 bg-slate-50 border rounded text-xs">
                  <div className="text-slate-500">{n.author} · {n.created_at}</div>
                  <div className="mt-1 text-slate-800">{n.text}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
