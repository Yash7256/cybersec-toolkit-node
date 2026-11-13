import ScanSummaryHero from './ScanSummaryHero';
import NetworkAnalysisTabs from './NetworkAnalysisTabs';
import ExportShareSection from './ExportShareSection';

export default function TracerouteResultsPage({
  result,
  loading = false,
  error = null,
  onExportPdf,
  onExportJson,
  onExportCsv,
  onShare,
  monitoringPanel,
  hopTimeline,
}) {
  return (
    <div className="flex flex-col gap-6 min-w-0">
      {error && (
        <section className="rounded-xl border border-[#FF4D4D] bg-[#201330]/82 p-7 shadow-[0_18px_60px_rgba(0,0,0,0.18)] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
          <p className="m-0 text-[#FF4D4D]">Traceroute failed: {error}</p>
        </section>
      )}

      {loading && !result && (
        <section className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-7 shadow-[0_18px_60px_rgba(0,0,0,0.18)] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
          <p className="m-0 text-[#aaaaaa]">Running traceroute...</p>
        </section>
      )}

      {!loading && !result && !error && (
        <section className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-7 shadow-[0_18px_60px_rgba(0,0,0,0.18)] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
          <p className="m-0 text-[#aaaaaa]">Enter a domain or IP address above and run a traceroute to see results.</p>
        </section>
      )}

      {result && (
        <>
          <ScanSummaryHero data={result.summary} />
          <NetworkAnalysisTabs data={result.networkAnalysis} monitoringPanel={monitoringPanel} hopTimeline={hopTimeline} />
          <ExportShareSection
            onExportPdf={onExportPdf}
            onExportJson={onExportJson}
            onExportCsv={onExportCsv}
            onShare={onShare}
          />
        </>
      )}
    </div>
  );
}
