/**
 * Shared export utilities for all cybersec toolkit tools.
 * Provides consistent download, branded-PDF and share behaviour.
 */

// ─── Download ────────────────────────────────────────────────────────────────

/**
 * Trigger a file download from an in-memory string.
 * @param {string} filename
 * @param {string} content
 * @param {string} mimeType
 */
export function downloadFile(filename, content, mimeType = 'text/plain') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Branded PDF ─────────────────────────────────────────────────────────────

const PRINT_HEADER_ID = '__cs_print_header__';
const PRINT_STYLE_ID  = '__cs_print_style__';

/**
 * Injects a branded print-only header into the page and triggers window.print().
 * The header is removed once the print dialog closes.
 *
 * @param {object} opts
 * @param {string} opts.tool        - Tool name, e.g. "Port Scanner"
 * @param {string} opts.target      - The scanned target
 * @param {string} [opts.subtitle]  - Optional extra subtitle line
 */
export function exportBrandedPdf({ tool = '', target = '', subtitle = '' } = {}) {
  // Remove any stale injected elements
  document.getElementById(PRINT_HEADER_ID)?.remove();
  document.getElementById(PRINT_STYLE_ID)?.remove();

  const now = new Date().toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  });

  // Branded header rendered only during print
  const header = document.createElement('div');
  header.id = PRINT_HEADER_ID;
  header.innerHTML = `
    <div style="
      display:flex;align-items:center;gap:14px;
      border-bottom:2px solid #7c3aed;
      padding-bottom:14px;margin-bottom:18px;
    ">
      <img src="/assets/logo.svg" alt="CyberSec Toolkit"
        style="width:48px;height:48px;flex-shrink:0;" />
      <div style="flex:1;min-width:0;">
        <div style="font-size:20px;font-weight:700;color:#1e1033;letter-spacing:-0.3px;">
          CyberSec Toolkit
        </div>
        <div style="font-size:12px;color:#6b21a8;font-weight:600;margin-top:2px;text-transform:uppercase;letter-spacing:0.5px;">
          ${tool}${target ? ` — ${target}` : ''}
        </div>
        ${subtitle ? `<div style="font-size:11px;color:#7c3aed;margin-top:2px;">${subtitle}</div>` : ''}
      </div>
      <div style="text-align:right;font-size:10px;color:#9ca3af;flex-shrink:0;">
        <div>Generated ${now}</div>
        <div style="margin-top:2px;color:#7c3aed;font-weight:600;">cybersec-toolkit</div>
      </div>
    </div>
  `;

  // Print-only CSS: show header, hide non-essential chrome
  const style = document.createElement('style');
  style.id = PRINT_STYLE_ID;
  style.textContent = `
    @media print {
      #${PRINT_HEADER_ID} { display: flex !important; }
      /* hide sidebar, nav, input bars, run buttons */
      .scanner-control-shell,
      .scanner-title-row,
      nav, aside, header,
      .run-btn, .clear-input-btn { display: none !important; }
      body { background: #fff !important; color: #111 !important; }
    }
    @media screen {
      #${PRINT_HEADER_ID} { display: none !important; }
    }
  `;

  document.body.prepend(header);
  document.head.appendChild(style);

  // Trigger print and clean up afterwards
  const cleanup = () => {
    document.getElementById(PRINT_HEADER_ID)?.remove();
    document.getElementById(PRINT_STYLE_ID)?.remove();
  };

  // afterprint fires when the dialog closes (print or cancel)
  window.addEventListener('afterprint', cleanup, { once: true });
  // Fallback: also clean up on next render cycle in case afterprint doesn't fire
  setTimeout(cleanup, 60_000);

  window.print();
}

// ─── Share / Copy ─────────────────────────────────────────────────────────────

/**
 * Share text via Web Share API, falling back to clipboard copy.
 * Returns true if the native share sheet was used, false if clipboard fallback.
 *
 * @param {object} opts
 * @param {string} opts.title
 * @param {string} opts.text
 * @returns {Promise<boolean>}
 */
export async function shareOrCopy({ title = 'CyberSec Toolkit Report', text = '' } = {}) {
  if (navigator.share) {
    try {
      await navigator.share({ title, text });
      return true;
    } catch {
      // User cancelled or share failed — fall through to clipboard
    }
  }
  await navigator.clipboard.writeText(text).catch(() => {});
  return false;
}

// ─── CSV helpers ─────────────────────────────────────────────────────────────

/** Escape a single CSV cell value. */
export const csvEscape = (value) =>
  `"${String(value ?? '').replaceAll('"', '""')}"`;

/** Convert an array of row-arrays to a CSV string. */
export const rowsToCsv = (rows) =>
  rows.map((row) => row.map(csvEscape).join(',')).join('\n');
