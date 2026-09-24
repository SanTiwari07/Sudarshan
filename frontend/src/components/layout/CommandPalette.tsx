import { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  FileText,
  Database,
  Globe,
  Sparkles,
  Layers,
  Compass,
  Settings,
  History,
  ShieldAlert,
  ArrowRight,
  X,
} from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';
import { useInvestigationUI } from '../../context/InvestigationUIContext';

interface CommandItem {
  id: string;
  category: 'Navigation' | 'Case Sections' | 'Evidence';
  title: string;
  subtitle?: string;
  icon: typeof Search;
  action: () => void;
  badge?: string;
}

export default function CommandPalette({
  isOpen,
  onClose,
}: {
  isOpen: boolean;
  onClose: () => void;
}) {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const { analysisResult, investigationBundle } = useAnalysis();
  const { openEvidence } = useInvestigationUI();

  const sha256 = analysisResult?.sha256;

  // Reset state when opened
  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  // Construct items
  const items = useMemo<CommandItem[]>(() => {
    const list: CommandItem[] = [];

    if (sha256) {
      list.push(
        {
          id: 'case-summary',
          category: 'Case Sections',
          title: 'Case Overview',
          subtitle: `Active Case: ${analysisResult?.package_name || sha256.slice(0, 12)}`,
          icon: FileText,
          action: () => navigate(`/case/${sha256}`),
        },
        {
          id: 'case-evidence',
          category: 'Case Sections',
          title: 'Evidence Explorer',
          subtitle: 'Static, runtime, visual, network and raw forensic records',
          icon: Database,
          action: () => navigate(`/case/${sha256}/evidence`),
        },
        {
          id: 'case-intel',
          category: 'Case Sections',
          title: 'Threat Intelligence',
          subtitle: 'Correlation, IOCs, campaign attribution, and threat feeds',
          icon: Globe,
          action: () => navigate(`/case/${sha256}/intel`),
        },
        {
          id: 'case-ask',
          category: 'Case Sections',
          title: 'Ask Sudarshan AI',
          subtitle: 'Advisory investigation assistant and natural language inquiries',
          icon: Sparkles,
          action: () => navigate(`/case/${sha256}/ask`),
        },
      );
    }

    list.push(
      {
        id: 'nav-history',
        category: 'Navigation',
        title: 'Cases & History',
        subtitle: 'View all analyzed mobile samples and previous investigations',
        icon: History,
        action: () => navigate('/history'),
      },
      {
        id: 'nav-batch',
        category: 'Navigation',
        title: 'Batch Scan',
        subtitle: 'Bulk analysis for multi-APK triage',
        icon: Layers,
        action: () => navigate('/batch'),
      },
      {
        id: 'nav-discovery',
        category: 'Navigation',
        title: 'URL & Threat Discovery',
        subtitle: 'Inspect landing pages and APK distribution servers',
        icon: Compass,
        action: () => navigate('/discovery'),
      },
      {
        id: 'nav-settings',
        category: 'Navigation',
        title: 'Settings & Preferences',
        subtitle: 'Operator settings, key bindings, and risk thresholds',
        icon: Settings,
        action: () => navigate('/settings'),
      },
    );

    // If query has text, also search evidence records
    if (query.trim() && investigationBundle?.evidenceRecords) {
      const q = query.toLowerCase().trim();
      const matchedRecords = investigationBundle.evidenceRecords
        .filter(
          (r) =>
            r.id.toLowerCase().includes(q) ||
            r.title.toLowerCase().includes(q) ||
            (r.description && r.description.toLowerCase().includes(q)) ||
            (r.hookNames && r.hookNames.some((h) => h.toLowerCase().includes(q))),
        )
        .slice(0, 8);

      matchedRecords.forEach((record) => {
        list.push({
          id: `evidence-${record.id}`,
          category: 'Evidence',
          title: `${record.id}: ${record.title}`,
          subtitle: record.description || record.category,
          icon: ShieldAlert,
          badge: record.severity.toUpperCase(),
          action: () => openEvidence(record.id),
        });
      });
    }

    return list;
  }, [sha256, analysisResult, investigationBundle, query, navigate, openEvidence]);

  const filteredItems = useMemo(() => {
    if (!query.trim()) return items;
    const q = query.toLowerCase().trim();
    return items.filter(
      (item) =>
        item.title.toLowerCase().includes(q) ||
        (item.subtitle && item.subtitle.toLowerCase().includes(q)) ||
        item.category.toLowerCase().includes(q),
    );
  }, [items, query]);

  // Adjust selectedIndex if out of bounds
  useEffect(() => {
    if (selectedIndex >= filteredItems.length) {
      setSelectedIndex(Math.max(0, filteredItems.length - 1));
    }
  }, [filteredItems, selectedIndex]);

  // Keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % Math.max(1, filteredItems.length));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + filteredItems.length) % Math.max(1, filteredItems.length));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredItems[selectedIndex]) {
        filteredItems[selectedIndex].action();
        onClose();
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal Dialog */}
      <div
        className="relative w-full max-w-2xl bg-white rounded-xl shadow-2xl border border-slate-200 overflow-hidden z-10 flex flex-col max-h-[80vh] animate-in fade-in zoom-in-95 duration-150"
        onKeyDown={handleKeyDown}
      >
        {/* Search Input Bar */}
        <div className="flex items-center px-4 py-3.5 border-b border-slate-200 gap-3 bg-slate-50/50">
          <Search className="h-5 w-5 text-slate-400 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            placeholder="Type a command, section, or search evidence... (Esc to close)"
            className="flex-1 bg-transparent border-0 text-slate-900 placeholder:text-slate-400 text-sm focus:outline-none focus:ring-0"
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              className="p-1 text-slate-400 hover:text-slate-600 rounded"
              title="Clear search"
            >
              <X className="h-4 w-4" />
            </button>
          )}
          <kbd className="hidden sm:inline-flex items-center px-2 py-0.5 text-[11px] font-semibold text-slate-500 bg-white border border-slate-200 rounded shadow-xs">
            ESC
          </kbd>
        </div>

        {/* Results List */}
        <div ref={listRef} className="flex-1 overflow-y-auto p-2 space-y-1">
          {filteredItems.length === 0 ? (
            <div className="py-12 text-center text-sm text-slate-500">
              No matching commands or evidence records found for "{query}".
            </div>
          ) : (
            filteredItems.map((item, index) => {
              const Icon = item.icon;
              const isSelected = index === selectedIndex;
              return (
                <div
                  key={item.id}
                  onClick={() => {
                    item.action();
                    onClose();
                  }}
                  onMouseEnter={() => setSelectedIndex(index)}
                  className={`flex items-center justify-between px-3 py-2.5 rounded-lg cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-blue-50 text-blue-900'
                      : 'text-slate-700 hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div
                      className={`p-1.5 rounded-md shrink-0 ${
                        isSelected
                          ? 'bg-blue-600 text-white'
                          : 'bg-slate-100 text-slate-600'
                      }`}
                    >
                      <Icon className="h-4 w-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold truncate">
                          {item.title}
                        </span>
                        <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-slate-100 text-slate-500 border border-slate-200">
                          {item.category}
                        </span>
                        {item.badge && (
                          <span
                            className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                              item.badge === 'CRITICAL' || item.badge === 'HIGH'
                                ? 'bg-red-50 text-red-700 border-red-200'
                                : 'bg-amber-50 text-amber-700 border-amber-200'
                            }`}
                          >
                            {item.badge}
                          </span>
                        )}
                      </div>
                      {item.subtitle && (
                        <p className="text-xs text-slate-500 truncate mt-0.5">
                          {item.subtitle}
                        </p>
                      )}
                    </div>
                  </div>
                  {isSelected && (
                    <ArrowRight className="h-4 w-4 text-blue-600 shrink-0 ml-2" />
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="px-4 py-2 bg-slate-50 border-t border-slate-200 flex items-center justify-between text-xs text-slate-500">
          <div className="flex items-center gap-3">
            <span>
              <kbd className="font-mono bg-white px-1.5 py-0.5 rounded border border-slate-200 shadow-2xs mr-1">↑</kbd>
              <kbd className="font-mono bg-white px-1.5 py-0.5 rounded border border-slate-200 shadow-2xs mr-1">↓</kbd>
              Navigate
            </span>
            <span>
              <kbd className="font-mono bg-white px-1.5 py-0.5 rounded border border-slate-200 shadow-2xs mr-1">↵</kbd>
              Select
            </span>
          </div>
          <span>SUDARSHAN Command Palette</span>
        </div>
      </div>
    </div>
  );
}
