export type BatchJobStatus = 'QUEUED' | 'SCANNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export type BatchStatus =
  | 'QUEUED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'PARTIAL'
  | 'FAILED'
  | 'CANCELLED'
  | 'PAUSED';

export interface BatchJob {
  job_id: string;
  batch_id: string;
  filename: string;
  sha256?: string | null;
  queue_position: number;
  status: BatchJobStatus;
  progress_pct: number;
  current_stage?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  error?: string | null;
  case_sha256?: string | null;
  // Enriched case info if fetched/available
  final_risk_score?: number | null;
  risk_band?: string | null;
}

export interface BatchSummary {
  batch_id: string;
  created_by: number;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  total_jobs: number;
  completed_jobs: number;
  failed_jobs: number;
  cancelled_jobs: number;
  status: BatchStatus;
  current_job_id?: string | null;
  progress_pct: number;
  // Risk counts summary if available
  critical_count?: number;
  high_risk_count?: number;
  suspicious_count?: number;
  safe_count?: number;
}

export interface BatchDetail extends BatchSummary {
  jobs: BatchJob[];
}

export interface BatchListResponse {
  total: number;
  limit: number;
  offset: number;
  batches: BatchSummary[];
}

export interface BatchCreateResponse {
  batch_id: string;
  total_jobs: number;
  status: BatchStatus;
  message: string;
  jobs: BatchJob[];
}
