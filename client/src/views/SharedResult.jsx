import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';
import GeoIPResultsPage from '../components/geoip/GeoIPResultsPage';

export default function SharedResult() {
  const { token } = useParams();
  const [state, setState] = useState({ loading: true, error: '', data: null });

  useEffect(() => {
    const meta = document.createElement('meta');
    meta.name = 'robots';
    meta.content = 'noindex, nofollow';
    document.head.appendChild(meta);
    return () => meta.remove();
  }, []);

  useEffect(() => {
    let active = true;
    fetch(`${import.meta.env.VITE_API_BASE_URL || ''}/api/share/${encodeURIComponent(token)}`)
      .then(async (response) => {
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || 'Share link not found');
        if (active) setState({ loading: false, error: '', data: payload });
      })
      .catch((err) => {
        if (active) setState({ loading: false, error: err.message, data: null });
      });
    return () => { active = false; };
  }, [token]);

  return (
    <div className="min-h-screen bg-[#0b0618] px-4 py-8 text-white">
      <div className="mx-auto max-w-5xl space-y-4">
        <div className="flex items-center gap-2 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]">
          <ShieldCheck className="h-4 w-4" /> Shared CyberSec Toolkit result
        </div>
        {state.loading && <div className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-8 text-sm text-[#aaaaaa]">Loading shared result…</div>}
        {state.error && <div className="rounded-xl border border-[#FF4D4D]/30 bg-[#FF4D4D]/10 p-6 text-sm text-[#FF9B9B]">{state.error}</div>}
        {state.data && (
          <>
            <div className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-5">
              <div className="text-[11px] uppercase tracking-wider text-[#ba9cff]">{state.data.tool}</div>
              <div className="mt-1 font-mono text-lg text-white">{state.data.target}</div>
              <div className="mt-1 text-[11px] text-[#aaaaaa]">Expires {new Date(state.data.expiresAt).toLocaleString()}</div>
            </div>
            {state.data.tool === 'GEOIP'
              ? <GeoIPResultsPage result={state.data.data} copied="" onCopy={() => {}} onDownload={() => {}} />
              : <pre className="overflow-auto rounded-xl border border-white/[0.14] bg-[#190f23]/80 p-5 text-[11px] text-[#ded4e9]">{JSON.stringify(state.data.data, null, 2)}</pre>}
          </>
        )}
      </div>
    </div>
  );
}
