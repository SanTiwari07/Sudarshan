import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { UploadCloud, AlertTriangle, Loader2, Shield } from 'lucide-react';
import type { FraudCardData } from '../App';
import { getToken } from './Login';
import { API_BASE } from '../config';
import { SocCard } from '../components/ui/Card';

export default function Upload({ onAnalysisComplete }: { onAnalysisComplete: (data: FraudCardData) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const token = getToken();
      const response = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: formData,
      });

      if (response.status === 401) {
        navigate('/login');
        return;
      }

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Analysis failed');
      }

      const data: FraudCardData = await response.json();
      onAnalysisComplete(data);
      navigate('/fraud-card');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred during APK analysis pipeline execution.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto mt-12">
      <SocCard className="p-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-blue-50 text-blue-700 mb-3">
            <Shield className="h-6 w-6" />
          </div>
          <h2 className="text-2xl font-bold text-slate-900">Upload APK for Analysis</h2>
          <p className="text-slate-500 mt-2 text-sm">
            Submit an Android package to the Sudarshan dual-audience intelligence engine.
          </p>
        </div>

        <form onSubmit={handleUpload} className="space-y-6">
          <div className="border-2 border-dashed border-slate-300 rounded-lg p-10 text-center hover:bg-slate-50 transition-colors">
            <input
              type="file"
              accept=".apk"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="hidden"
              id="apk-upload"
            />
            <label htmlFor="apk-upload" className="cursor-pointer flex flex-col items-center justify-center">
              <UploadCloud className="h-12 w-12 text-blue-600 mb-4" />
              <span className="text-lg font-medium text-blue-700">Select APK File</span>
              <span className="text-sm text-slate-400 mt-1">{file ? file.name : 'No file selected'}</span>
            </label>
          </div>

          {error && (
            <div className="bg-red-50 border-l-4 border-red-500 p-4 flex items-start">
              <AlertTriangle className="h-5 w-5 text-red-500 mr-3 mt-0.5 flex-shrink-0" />
              <div>
                <h3 className="text-sm font-medium text-red-800">Pipeline Error</h3>
                <p className="text-sm text-red-700 mt-1">{error}</p>
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={!file || loading}
            className="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-slate-400 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? (
              <>
                <Loader2 className="animate-spin h-5 w-5 mr-3" />
                Executing Pipeline Analysis...
              </>
            ) : (
              'Analyze Application'
            )}
          </button>
        </form>
      </SocCard>
    </div>
  );
}
