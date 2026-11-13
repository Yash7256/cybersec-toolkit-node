import { FileText, Share2 } from 'lucide-react';

export default function ExportShareSection({ onExportPdf, onExportJson, onExportCsv, onShare }) {
  return (
    <section className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-10 shadow-[0_18px_60px_rgba(0,0,0,0.18)] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
      <h3 className="text-[18px] font-semibold uppercase text-[#ba9cff]">Export &amp; Share</h3>
      <p className="mt-4 text-[14px] text-[#ded4e9]">Download or share your scan report.</p>
      <div className="mt-8 grid grid-cols-4 gap-4 max-md:grid-cols-2">
        <button onClick={onExportPdf} className="flex h-16 cursor-pointer items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 px-5 text-[13px] text-white transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
          <FileText size={20} /> Export PDF
        </button>
        <button onClick={onExportJson} className="flex h-16 cursor-pointer items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 px-5 text-[13px] text-white transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
          <FileText size={20} /> Export JSON
        </button>
        <button onClick={onExportCsv} className="flex h-16 cursor-pointer items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 px-5 text-[13px] text-white transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
          <FileText size={20} /> Export CSV
        </button>
        <button onClick={onShare} className="flex h-16 cursor-pointer items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 px-5 text-[13px] text-white transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
          <Share2 size={20} /> Share report
        </button>
      </div>
    </section>
  );
}
