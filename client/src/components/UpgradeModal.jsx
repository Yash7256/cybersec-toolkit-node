/**
 * UpgradeModal — full-screen overlay shown when a free-tier user hits their
 * daily tool-use limit.
 *
 * Listens to the global 'tier:limit_reached' DOM event and can also be
 * controlled via props (open / onClose).
 */
import { useEffect, useState } from 'react';
import {
  CheckCircle2,
  Crown,
  Infinity as InfinityIcon,
  Shield,
  Sparkles,
  X,
  Zap,
} from 'lucide-react';
import { useTier } from '../context/TierContext';

// ─── Comparison table data ──────────────────────────────────────────────────

const FREE_FEATURES = [
  { label: '5 tool scans per day', ok: true },
  { label: 'DNS, WHOIS, GeoIP', ok: true },
  { label: 'Port Scanner (common ports)', ok: true },
  { label: 'Subdomain & OS Fingerprint', ok: true },
  { label: 'Unlimited daily scans', ok: false },
  { label: 'AI-powered analysis', ok: false },
  { label: 'Scan history & exports', ok: false },
  { label: 'Priority support', ok: false },
];

const PAID_FEATURES = [
  { label: 'Unlimited tool scans', ok: true },
  { label: 'All tools — no restrictions', ok: true },
  { label: 'Full AI-powered analysis', ok: true },
  { label: 'Scan history & PDF exports', ok: true },
  { label: 'CVE & exploit intelligence', ok: true },
  { label: 'Web App vulnerability scanner', ok: true },
  { label: 'Priority support', ok: true },
  { label: 'API access', ok: true },
];

// ─── Sub-components ─────────────────────────────────────────────────────────

function FeatureRow({ label, ok, muted = false }) {
  return (
    <div className="flex items-center gap-3 py-2 border-b border-white/5 last:border-0">
      {ok ? (
        <CheckCircle2 className="w-4 h-4 shrink-0" style={{ color: '#7CFF9A' }} />
      ) : (
        <X className="w-4 h-4 shrink-0" style={{ color: '#6b5fa0' }} />
      )}
      <span
        className="text-sm"
        style={{ color: ok ? (muted ? '#c4b5fd' : '#e9d5ff') : '#6b5fa0' }}
      >
        {label}
      </span>
    </div>
  );
}

// ─── Main component ─────────────────────────────────────────────────────────

export default function UpgradeModal({ open: controlledOpen, onClose: controlledClose }) {
  const [internalOpen, setInternalOpen] = useState(false);
  const { toolUsage, limit } = useTier();

  // Find the tool(s) that hit their limit (remaining === 0)
  const limitedTools = Object.entries(toolUsage).filter(([, v]) => v.remaining === 0);
  const limitedToolName = limitedTools.length === 1
    ? limitedTools[0][0]
    : limitedTools.length > 1
      ? `${limitedTools.length} tools`
      : 'this tool';

  // For the progress bar, use the triggered tool's count if unambiguous
  const triggeredEntry = limitedTools.length === 1 ? limitedTools[0][1] : null;
  const dailyUsage = triggeredEntry ? triggeredEntry.count : limit;
  const remaining = triggeredEntry ? triggeredEntry.remaining : 0;

  // Respond to global event
  useEffect(() => {
    const handler = () => setInternalOpen(true);
    window.addEventListener('tier:limit_reached', handler);
    return () => window.removeEventListener('tier:limit_reached', handler);
  }, []);

  const isOpen = controlledOpen ?? internalOpen;

  const close = () => {
    setInternalOpen(false);
    controlledClose?.();
  };

  // Respond to Escape key
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  if (!isOpen) return null;

  return (
    <div
      className="upgrade-modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="upgrade-modal-title"
      onClick={close}
    >
      <div
        className="upgrade-modal"
        onClick={(e) => e.stopPropagation()}
      >
        {/* ── Close button ──────────────────────────────────────────── */}
        <button
          type="button"
          onClick={close}
          className="upgrade-modal-close"
          aria-label="Close upgrade modal"
        >
          <X className="w-5 h-5" />
        </button>

        {/* ── Header ───────────────────────────────────────────────── */}
        <div className="upgrade-modal-header">
          <div className="upgrade-modal-icon">
            <Zap className="w-7 h-7" style={{ color: '#F97316' }} />
          </div>
          <h2 id="upgrade-modal-title" className="upgrade-modal-title">
            Daily limit reached
          </h2>
          <p className="upgrade-modal-subtitle">
            You've used{' '}
            <strong style={{ color: '#FF4D4D' }}>
              {dailyUsage}/{limit}
            </strong>{' '}
            free uses of <strong style={{ color: '#FF4D4D' }}>{limitedToolName}</strong> today.
            Each tool allows {limit} free uses per day. Upgrade to Paid for unlimited access.
          </p>

          {/* Usage bar */}
          <div className="upgrade-usage-bar-wrap">
            <div
              className="upgrade-usage-bar-fill"
              style={{ width: limit > 0 ? `${(dailyUsage / limit) * 100}%` : '100%' }}
            />
          </div>
          <p className="upgrade-usage-label">
            {remaining === 0
              ? `No uses of ${limitedToolName} remaining today`
              : `${remaining} use${remaining === 1 ? '' : 's'} remaining`}
          </p>
        </div>

        {/* ── Tier comparison ──────────────────────────────────────── */}
        <div className="upgrade-tier-grid">
          {/* Free column */}
          <div className="upgrade-tier-card">
            <div className="upgrade-tier-card-header free">
              <Shield className="w-5 h-5" />
              <span>Free</span>
            </div>
            <div className="upgrade-tier-price">
              <span className="upgrade-tier-price-value">$0</span>
              <span className="upgrade-tier-price-period">/ mo</span>
            </div>
            <div className="upgrade-tier-features">
              {FREE_FEATURES.map((f) => (
                <FeatureRow key={f.label} {...f} muted />
              ))}
            </div>
          </div>

          {/* Paid column */}
          <div className="upgrade-tier-card paid">
            <div className="upgrade-tier-card-header paid-header">
              <Crown className="w-5 h-5" style={{ color: '#F97316' }} />
              <span>Paid</span>
              <span className="upgrade-tier-popular-badge">
                <Sparkles className="w-3 h-3" />
                Popular
              </span>
            </div>
            <div className="upgrade-tier-price">
              <span className="upgrade-tier-price-value paid-price">$9</span>
              <span className="upgrade-tier-price-period">/ mo</span>
            </div>
            <div className="upgrade-tier-features">
              {PAID_FEATURES.map((f) => (
                <FeatureRow key={f.label} {...f} />
              ))}
            </div>
            <div className="upgrade-tier-unlimited">
              <InfinityIcon className="w-4 h-4" style={{ color: '#a78bfa' }} />
              <span>Unlimited scans every day</span>
            </div>
          </div>
        </div>

        {/* ── CTA ──────────────────────────────────────────────────── */}
        <div className="upgrade-modal-footer">
          <a
            href="#upgrade"
            className="upgrade-cta-btn"
            onClick={(e) => { e.preventDefault(); }}
          >
            <Crown className="w-5 h-5" style={{ color: '#F97316' }} />
            Upgrade to Paid — $9/mo
          </a>
          <button type="button" className="upgrade-dismiss-btn" onClick={close}>
            Continue with Free
          </button>
        </div>
      </div>
    </div>
  );
}
