import { useState, useRef, useEffect } from 'react';
import {
  Layers,
  UploadCloud,
  FileCheck2,
  AlertTriangle,
  Play,
  Loader2,
  PlusCircle,
  History,
  X,
} from 'lucide-react';
import { SocCard } from '../ui/Card';
import BatchProgressBar from './BatchProgressBar';
import BatchJobRow from './BatchJobRow';
import BatchHistory from './BatchHistory';
import { useBatchProgress } from './useBatchProgress';
import { API_BASE, authHeaders } from '../../config';
import { TYPOGRAPHY } from '../../theme/typography';
import type { BatchCreateResponse } from '../../types/batch';

const STORAGE_ACTIVE_BATCH_KEY = 'sudarshan_active_batch_id';

export default function BatchScanPage() {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [activeTab, setActiveTab] = useState<'scan' | 'history'>('scan');
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // Active batch ID stored in localStorage so live in-progress page refresh reconstructs state
  const [activeBatchId, setActiveBatchId] = useState<string | null>(() => {
    return localStorage.getItem(STORAGE_ACTIVE_BATCH_KEY) || null;
  });
  const [sessionBatchId, setSessionBatchId] = useState<string | null>(null);

  const {
    batch,
    actionLoading,
    pauseBatch,
    resumeBatch,
    cancelBatch,
    retryJob,
  } = useBatchProgress(activeBatchId);

  const isTerminal =
    batch?.status === 'COMPLETED' ||
    batch?.status === 'PARTIAL' ||
    batch?.status === 'FAILED' ||
    batch?.status === 'CANCELLED';

  const isLiveScanning = batch && !isTerminal;
  const showBatchProgress = Boolean(
    activeBatchId && batch && (isLiveScanning || activeBatchId === sessionBatchId)
  );

  // When batch reaches terminal status or if not scanning, remove from active storage so new visits open new scan
  useEffect(() => {
    if (isTerminal) {
      localStorage.removeItem(STORAGE_ACTIVE_BATCH_KEY);
    }
  }, [isTerminal]);

  // Sync activeBatchId to localStorage only if live scanning or created in session
  useEffect(() => {
    if (activeBatchId && !isTerminal) {
      localStorage.setItem(STORAGE_ACTIVE_BATCH_KEY, activeBatchId);
    } else if (isTerminal) {
      localStorage.removeItem(STORAGE_ACTIVE_BATCH_KEY);
    }
  }, [activeBatchId, isTerminal]);

  const resetNewBatch = () => {
    setActiveBatchId(null);
    setSessionBatchId(null);
    setSelectedFiles([]);
    localStorage.removeItem(STORAGE_ACTIVE_BATCH_KEY);
  };

  const handleFileSelect = (files: FileList | null) => {
    if (!files) return;
    setUploadError(null);

    const validApks: File[] = [];
    const invalidNames: string[] = [];

    Array.from(files).forEach((f) => {
      if (f.name.toLowerCase().endsWith('.apk')) {
        // Prevent duplicate file objects in the selection list
        if (!selectedFiles.some((existing) => existing.name === f.name && existing.size === f.size)) {
          validApks.push(f);
        }
      } else {
        invalidNames.push(f.name);
      }
    });

    if (invalidNames.length > 0) {
      setUploadError(`Ignored ${invalidNames.length} non-APK file(s): ${invalidNames.slice(0, 3).join(', ')}`);
    }

    if (selectedFiles.length + validApks.length > 50) {
      setUploadError('Maximum 50 APK files per batch.');
      return;
    }

    setSelectedFiles((prev) => [...prev, ...validApks]);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer.files) {
      handleFileSelect(e.dataTransfer.files);
    }
  };

  const removeFile = (index: number) => {
    setSelectedFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const clearFiles = () => {
    setSelectedFiles([]);
    setUploadError(null);
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toFixed(1)} KB`;
    }
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const startBatchScan = async () => {
    if (selectedFiles.length < 2) {
      setUploadError('Please select at least 2 APK files for a batch scan.');
      return;
    }

    setIsUploading(true);
    setUploadError(null);
    setUploadProgress(10);

    const formData = new FormData();
    selectedFiles.forEach((file) => {
      formData.append('files', file);
    });

    try {
      setUploadProgress(40);
      const res = await fetch(`${API_BASE}/batches`, {
        method: 'POST',
        headers: authHeaders(),
        body: formData,
      });

      setUploadProgress(90);

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || 'Failed to initialize batch scan');
      }

      const data: BatchCreateResponse = await res.json();
      setUploadProgress(100);
      setActiveBatchId(data.batch_id);
      setSessionBatchId(data.batch_id);
      setSelectedFiles([]);
    } catch (err: any) {
      setUploadError(err.message || 'Batch creation failed.');
    } finally {
      setIsUploading(false);
    }
  };

  const currentScanningJob = batch?.jobs?.find((j) => j.status === 'SCANNING');

  return (
    <div className="w-full min-w-0 space-y-4">
      {/* Navigation Tabs */}
        <div className="flex border-b border-slate-200 justify-between items-center">
          <div className="flex space-x-2">
            <button
              onClick={() => {
                setActiveTab('scan');
                if (isTerminal) {
                  resetNewBatch();
                }
              }}
              className={`px-5 py-3 ${TYPOGRAPHY.button} border-b-2 transition-colors flex items-center gap-2 cursor-pointer ${
                activeTab === 'scan'
                  ? 'border-blue-600 text-blue-700 bg-blue-50/50'
                  : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
              }`}
            >
              <Layers className="w-4 h-4" />
              <span>Enterprise Batch Scan</span>
            </button>
            <button
              onClick={() => setActiveTab('history')}
              className={`px-5 py-3 ${TYPOGRAPHY.button} border-b-2 transition-colors flex items-center gap-2 cursor-pointer ${
                activeTab === 'history'
                  ? 'border-blue-600 text-blue-700 bg-blue-50/50'
                  : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
              }`}
            >
              <History className="w-4 h-4" />
              <span>Batch History</span>
            </button>
          </div>

          {showBatchProgress && activeTab === 'scan' && (
            <button
              type="button"
              onClick={resetNewBatch}
              className="text-xs font-semibold text-blue-600 hover:text-blue-800 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-50 border border-blue-100 hover:bg-blue-100 transition-colors cursor-pointer"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>New Batch</span>
            </button>
          )}
        </div>

        {activeTab === 'history' ? (
          <SocCard className="p-6 sm:p-8 border-slate-200/80 shadow-sm">
            <BatchHistory />
          </SocCard>
        ) : showBatchProgress && batch ? (
          /* ACTIVE BATCH VIEW */
          <div className="space-y-6">
            {/* Live Progress Card */}
            <SocCard className="p-6 sm:p-8 border-slate-200/80 shadow-sm">
              <div className="flex flex-wrap items-center justify-between gap-3 pb-6 border-b border-slate-100">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-blue-600 bg-blue-50 px-2.5 py-0.5 rounded-full border border-blue-100 font-mono">
                      Active Queue
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      ID: #{batch.batch_id.slice(0, 8)}
                    </span>
                  </div>
                  <h2 className="text-xl sm:text-2xl font-extrabold text-slate-900 font-mono tracking-tight mt-1">
                    Batch #{batch.batch_id.slice(0, 8)}
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5 font-mono">
                    FIFO Queue • 1 APK concurrently analyzed in sandbox
                  </p>
                </div>

                {/* Batch Actions */}
                <div className="flex items-center gap-2">
                  {batch.status === 'RUNNING' && (
                    <button
                      type="button"
                      onClick={pauseBatch}
                      disabled={actionLoading}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-amber-700 bg-amber-50 border border-amber-200 hover:bg-amber-100 shadow-2xs transition-colors cursor-pointer"
                    >
                      <span>Pause Queue</span>
                    </button>
                  )}
                  {batch.status === 'PAUSED' && (
                    <button
                      type="button"
                      onClick={resumeBatch}
                      disabled={actionLoading}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 hover:bg-emerald-100 shadow-2xs transition-colors cursor-pointer"
                    >
                      <span>Resume Queue</span>
                    </button>
                  )}
                  {batch.status !== 'COMPLETED' &&
                    batch.status !== 'FAILED' &&
                    batch.status !== 'CANCELLED' && (
                      <button
                        type="button"
                        onClick={cancelBatch}
                        disabled={actionLoading}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-red-700 bg-red-50 border border-red-200 hover:bg-red-100 shadow-2xs transition-colors cursor-pointer"
                      >
                        <span>Cancel Remaining</span>
                      </button>
                    )}
                </div>
              </div>

              {/* Progress Bar with Discrete Stats */}
              <div className="py-6 border-b border-slate-100">
                <BatchProgressBar batch={batch} />
              </div>

              {/* Currently Scanning Box */}
              {currentScanningJob && (
                <div className="pt-6">
                  <div className="p-4 rounded-xl bg-blue-50/60 border border-blue-100/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 rounded-lg bg-blue-600 text-white shrink-0">
                        <Loader2 className="w-5 h-5 animate-spin" />
                      </div>
                      <div>
                        <span className="text-[10px] font-bold text-blue-800 uppercase tracking-wider block font-mono">
                          Currently Scanning
                        </span>
                        <span className="text-sm font-bold text-slate-900 font-mono truncate max-w-md block" title={currentScanningJob.filename}>
                          {currentScanningJob.filename}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-semibold px-3 py-1 rounded-md bg-white border border-blue-200 text-blue-700 shadow-2xs">
                        Stage: {currentScanningJob.current_stage || 'Analyzing…'}
                      </span>
                      {currentScanningJob.progress_pct > 0 && (
                        <span className="text-xs font-mono font-bold text-slate-600">
                          {currentScanningJob.progress_pct}%
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </SocCard>

            {/* Live Results Table */}
            <SocCard className="overflow-hidden border-slate-200/80 shadow-sm">
              <div className="py-4 px-6 border-b border-slate-200/80 bg-surface-secondary flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-slate-900 font-mono uppercase tracking-wider flex items-center gap-2">
                    <Layers className="w-4 h-4 text-blue-600" />
                    Analysis Queue ({batch.jobs.length} APKs)
                  </h3>
                </div>
                <span className="text-xs text-slate-500 font-mono">
                  Auto-updating in background
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 text-[11px] font-bold text-slate-500 uppercase tracking-wider font-mono bg-surface-secondary">
                      <th className="py-3 px-4">APK File</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">Risk</th>
                      <th className="py-3 px-4">FRS</th>
                      <th className="py-3 px-4">Stage / SHA</th>
                      <th className="py-3 px-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {batch.jobs.map((job) => (
                      <BatchJobRow
                        key={job.job_id}
                        job={job}
                        onRetry={retryJob}
                        actionLoading={actionLoading}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            </SocCard>
          </div>
        ) : (
          /* MULTI-FILE UPLOAD ZONE */
          <SocCard className="p-8 sm:p-10 lg:p-12 border-slate-200/80 shadow-sm space-y-8">
            <div className="text-center max-w-xl mx-auto">
              <div className="inline-flex items-center justify-center p-3 bg-blue-50 rounded-2xl mb-3 text-blue-600">
                <Layers className="w-8 h-8" />
              </div>
              <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 font-mono tracking-tight">
                Enterprise Batch Scan
              </h1>
              <p className="text-sm text-slate-500 mt-2">
                Analyze multiple suspicious APKs in one controlled FIFO queue.
                Each APK is analyzed sequentially through the authoritative
                Sudarshan pipeline and saved as an independent Case.
              </p>
            </div>

            {/* Drop Zone */}
            <div
              onDragOver={(e) => {
                e.preventDefault();
                e.stopPropagation();
              }}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-slate-300 bg-surface-secondary hover:border-blue-500 hover:bg-blue-50/30 transition-all rounded-2xl p-8 sm:p-12 text-center cursor-pointer group"
            >
              <input
                ref={fileInputRef}
                type="file"
                multiple
                accept=".apk"
                className="hidden"
                onChange={(e) => handleFileSelect(e.target.files)}
              />
              <UploadCloud className="w-12 h-12 text-slate-400 group-hover:text-blue-600 transition-colors mx-auto mb-3" />
              <p className="text-base font-bold text-slate-800 group-hover:text-blue-900 transition-colors">
                Drag & drop multiple APKs here
              </p>
              <p className="text-xs text-slate-500 mt-1">
                or <span className="text-blue-600 font-semibold underline">browse from your computer</span>
              </p>
              <p className="text-[11px] text-slate-400 mt-3 font-mono">
                Supports 2 to 50 .apk files per batch • Up to 200MB each
              </p>
            </div>

            {uploadError && (
              <div className="p-4 rounded-xl bg-red-50 border border-red-200 flex items-start gap-3 text-red-800 text-xs">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <div className="flex-1">{uploadError}</div>
              </div>
            )}

            {/* Selected File List */}
            {selectedFiles.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold font-mono text-slate-700 uppercase tracking-wider">
                    Selected APKs ({selectedFiles.length})
                  </span>
                  <button
                    type="button"
                    onClick={clearFiles}
                    className="text-xs font-medium text-slate-500 hover:text-red-600 transition-colors cursor-pointer"
                  >
                    Clear all
                  </button>
                </div>

                <div className="max-h-64 overflow-y-auto rounded-xl border border-slate-200 divide-y divide-slate-100 bg-surface-secondary">
                  {selectedFiles.map((file, idx) => (
                    <div
                      key={`${file.name}-${idx}`}
                      className="py-2.5 px-4 flex items-center justify-between gap-3 text-xs"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <FileCheck2 className="w-4 h-4 text-blue-600 shrink-0" />
                        <span className="font-semibold text-slate-900 truncate" title={file.name}>
                          {file.name}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 shrink-0">
                        <span className="font-mono text-slate-500">
                          {formatFileSize(file.size)}
                        </span>
                        <span className="text-emerald-600 font-bold">✓</span>
                        <button
                          type="button"
                          onClick={() => removeFile(idx)}
                          className="p-1 rounded text-slate-400 hover:text-red-600 transition-colors"
                          title="Remove file"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Upload Progress bar when submitting */}
                {isUploading && (
                  <div className="space-y-2 pt-2">
                    <div className="flex justify-between text-xs font-mono text-slate-600">
                      <span>Uploading batch to Sudarshan gateway…</span>
                      <span>{uploadProgress}%</span>
                    </div>
                    <div className="h-2 w-full bg-slate-100 rounded-full overflow-hidden border border-slate-200">
                      <div
                        className="h-full bg-blue-600 transition-all duration-300"
                        style={{ width: `${uploadProgress}%` }}
                      />
                    </div>
                  </div>
                )}

                {/* Start Batch Button */}
                <button
                  type="button"
                  disabled={isUploading || selectedFiles.length < 2}
                  onClick={startBatchScan}
                  className={`mt-4 w-full h-14 flex justify-center items-center gap-2 rounded-xl ${TYPOGRAPHY.button} text-white bg-blue-700 shadow-sm hover:bg-blue-800 hover:shadow-md focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-blue-500 disabled:bg-slate-300 disabled:text-slate-500 disabled:cursor-not-allowed transition-all cursor-pointer`}
                >
                  {isUploading ? (
                    <>
                      <Loader2 className="w-5 h-5 animate-spin" />
                      <span>Creating Batch…</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 fill-white" />
                      <span>Start Enterprise Batch Scan ({selectedFiles.length} APKs)</span>
                    </>
                  )}
                </button>
              </div>
            )}
          </SocCard>
        )}
      </div>
  );
}
