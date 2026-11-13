import { useState } from 'react';
import { Brain, Loader } from 'lucide-react';

export default function AIExecutiveReport() {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const generate = async () => {
    setLoading(true);
    try {
      setReport({ error: 'AI executive reports are not available in this server build yet.' });
    } catch (e) { setReport({ error: e.message }); } finally { setLoading(false); }
  };

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-yellow-500/20 flex items-center justify-center">
            <Brain className="w-4 h-4 text-yellow-400" />
          </div>
          <h3 className="text-gray-100 font-display font-medium tracking-wide">AI Executive Report</h3>
          <div className="w-1.5 h-1.5 rounded-full bg-yellow-500 animate-pulse"></div>
        </div>
        <button onClick={generate} disabled={loading} className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-medium text-sm bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 hover:bg-yellow-500/20 transition-all disabled:opacity-50">
          {loading ? <Loader className="w-4 h-4 animate-spin" /> : <Brain className="w-4 h-4" />}
          Generate Report
        </button>
      </div>
      <div className="flex-1 bg-dark-900/30 border border-dark-600 rounded-2xl overflow-auto">
        {report === null && !loading ? (
          <div className="flex flex-col items-center justify-center h-full gap-6 p-8">
            <div className="w-20 h-20 rounded-full bg-yellow-500/10 border border-yellow-500/20 flex items-center justify-center">
              <Brain className="w-10 h-10 text-yellow-400 opacity-60" />
            </div>
            <div className="text-center">
              <div className="text-gray-400 font-display mb-2">AI-Powered Security Analysis</div>
              <p className="text-gray-600 text-sm max-w-sm">Generate an executive-level security summary from your recent scan results, including risk assessment and remediation recommendations.</p>
            </div>
          </div>
        ) : loading ? (
          <div className="flex flex-col items-center justify-center h-full gap-4">
            <div className="w-8 h-8 border-4 border-yellow-500/20 border-t-yellow-500 rounded-full animate-spin"></div>
            <div className="text-yellow-400 font-mono text-sm animate-pulse">Generating executive report...</div>
          </div>
        ) : report?.error ? (
          <div className="p-6 text-[#FF4D4D] font-mono text-sm">{report.error}</div>
        ) : (
          <div className="p-6 prose prose-invert max-w-none">
            <div className="text-gray-200 leading-relaxed whitespace-pre-wrap font-body">{report?.summary || JSON.stringify(report, null, 2)}</div>
          </div>
        )}
      </div>
    </div>
  );
}
