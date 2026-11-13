import { BrowserRouter, Routes, Route, Navigate, useParams, Outlet } from 'react-router-dom';
import { SignIn, SignUp, useAuth } from '@clerk/react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import PortScanner from './views/PortScanner';
import WebAppScanner from './views/WebAppScanner';
import DNSLookup from './views/DNSLookup';
import Whois from './views/Whois';
import Traceroute from './views/Traceroute';
import SSL from './views/SSL';
import GenericTool from './views/GenericTool';
import AIExecutiveReport from './views/AIExecutiveReport';
import Dashboard from './views/Dashboard';
import { TierProvider } from './context/TierContext';
import UpgradeModal from './components/UpgradeModal';

// ─── Auth page background wrapper style ──────────────────────────────────────
const authPageStyle = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  position: 'relative',
  overflow: 'hidden',
  minHeight: '100vh',
  width: '100%',
  background: '#0b0618',
  backgroundImage: 'url(/assets/GRID.png)',
  backgroundRepeat: 'no-repeat',
  backgroundPosition: 'center top',
  backgroundSize: 'auto 40%',
  padding: '20px 16px',
};

// ─── Shared Clerk appearance config ──────────────────────────────────────────
const clerkAppearance = {
  layout: {
    logoImageUrl: '/assets/logo.png',
    socialButtonsPlacement: 'top',
    socialButtonsVariant: 'blockButton',
    showOptionalFields: false,
  },
  elements: {
    // ── Root card ─────────────────────────────────────────────────────────────
    card: {
      background: 'rgba(255,255,255,0.06)',
      backdropFilter: 'blur(24px)',
      WebkitBackdropFilter: 'blur(24px)',
      borderRadius: '20px',
      border: '1px solid rgba(255,255,255,0.18)',
      boxShadow: [
        '0 16px 48px rgba(0,0,0,0.40)',
        'inset 0 1px 0 rgba(255,255,255,0.12)',
      ].join(', '),
      padding: '36px 32px 28px',
      width: '100%',
      maxWidth: '460px',
    },

    // ── Header ────────────────────────────────────────────────────────────────
    header: {
      textAlign: 'center',
      marginBottom: '20px',
      padding: '0',
    },
    logoBox: {
      margin: '0 auto 10px',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
    },
    logoImage: {
      width: '96px',
      height: '96px',
      objectFit: 'contain',
      filter: 'drop-shadow(0 0 22px rgba(139,92,246,0.65)) drop-shadow(0 0 8px rgba(167,139,250,0.45)) drop-shadow(0 2px 4px rgba(0,0,0,0.4))',
    },
    headerTitle: {
      fontSize: '28px',
      fontWeight: '700',
      color: '#f5f0ff',
      margin: '0 0 5px',
      fontFamily: "'Space Grotesk', 'Inter', sans-serif",
      letterSpacing: '-0.025em',
      lineHeight: '1.2',
    },
    headerSubtitle: {
      fontSize: '14px',
      fontWeight: '400',
      color: 'rgba(196,181,253,0.55)',
      margin: '0',
      lineHeight: '1.5',
      fontFamily: "'Inter', sans-serif",
      letterSpacing: '0.005em',
    },

    // ── Social buttons ────────────────────────────────────────────────────────
    socialButtonsRoot: {
      display: 'flex',
      flexDirection: 'column',
      gap: '9px',
      marginBottom: '0',
    },
    socialButtonsBlockButton: {
      borderRadius: '999px',
      height: '48px',
      width: '100%',
      background: '#ffffff',
      border: '1px solid rgba(0,0,0,0.08)',
      color: '#111111',
      fontSize: '14px',
      fontWeight: '500',
      fontFamily: "'Inter', sans-serif",
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: '10px',
      transition: 'all 0.2s cubic-bezier(0.4,0,0.2,1)',
      boxShadow: '0 1px 3px rgba(0,0,0,0.18)',
      cursor: 'pointer',
      letterSpacing: '0.01em',
    },
    socialButtonsBlockButton__github: {
      background: '#ffffff',
      border: '1px solid rgba(0,0,0,0.08)',
      color: '#111111',
    },
    socialButtonsBlockButton__google: {
      background: '#ffffff',
      border: '1px solid rgba(0,0,0,0.08)',
      color: '#111111',
    },
    socialButtonsBlockButtonText: {
      color: '#111111',
      fontSize: '14px',
      fontWeight: '500',
      fontFamily: "'Inter', sans-serif",
    },
    socialButtonsBlockButtonArrow: {
      display: 'none',
    },

    // ── OR divider ────────────────────────────────────────────────────────────
    dividerRow: {
      display: 'flex',
      alignItems: 'center',
      gap: '10px',
      padding: '14px 0',
    },
    dividerLine: {
      background: 'rgba(167,139,250,0.15)',
      height: '1px',
      flexGrow: '1',
    },
    dividerText: {
      color: 'rgba(196,181,253,0.38)',
      fontSize: '11px',
      fontWeight: '600',
      letterSpacing: '1.5px',
      textTransform: 'uppercase',
      fontFamily: "'Inter', sans-serif",
    },

    // ── Form fields ───────────────────────────────────────────────────────────
    form: {
      gap: '0',
    },
    formField: {
      marginBottom: '14px',
    },
    formFieldLabel: {
      color: 'rgba(196,181,253,0.7)',
      fontSize: '12px',
      fontWeight: '500',
      marginBottom: '7px',
      display: 'block',
      fontFamily: "'Inter', sans-serif",
      letterSpacing: '0.02em',
      textTransform: 'uppercase',
    },
    formFieldInput: {
      background: 'rgba(255,255,255,0.05)',
      backdropFilter: 'blur(8px)',
      WebkitBackdropFilter: 'blur(8px)',
      borderRadius: '12px',
      border: '1px solid rgba(167,139,250,0.14)',
      color: '#f0ebff',
      fontSize: '14px',
      height: '48px',
      padding: '0 16px',
      width: '100%',
      outline: 'none',
      transition: 'all 0.2s cubic-bezier(0.4,0,0.2,1)',
      fontFamily: "'Inter', sans-serif",
      boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.03)',
    },
    formFieldInputShowPasswordButton: {
      color: 'rgba(196,181,253,0.5)',
    },

    // ── Error states ──────────────────────────────────────────────────────────
    formFieldError: {
      color: '#FF4D4D',
      fontSize: '12px',
      fontWeight: '500',
      marginTop: '4px',
    },
    formFieldErrorText: {
      color: '#FF4D4D',
      fontSize: '12px',
    },

    // ── Primary CTA button ────────────────────────────────────────────────────
    formButtonPrimary: {
      borderRadius: '999px',
      height: '52px',
      width: '100%',
      background: 'linear-gradient(135deg, #c4b5fd 0%, #a78bfa 45%, #8b5cf6 100%)',
      border: 'none',
      color: '#150d2a',
      fontSize: '15px',
      fontWeight: '600',
      fontFamily: "'Space Grotesk', 'Inter', sans-serif",
      transition: 'all 0.25s cubic-bezier(0.4,0,0.2,1)',
      cursor: 'pointer',
      marginTop: '4px',
      letterSpacing: '0em',
      boxShadow: '0 4px 16px rgba(139,92,246,0.25)',
    },

    // ── Footer / switch links ─────────────────────────────────────────────────
    footer: {
      marginTop: '16px',
      textAlign: 'center',
      background: 'transparent',
      border: 'none',
      boxShadow: 'none',
      padding: '0',
    },
    footerAction: {
      textAlign: 'center',
    },
    footerActionText: {
      color: 'rgba(196,181,253,0.5)',
      fontSize: '13px',
      fontFamily: "'Inter', sans-serif",
    },
    footerActionLink: {
      color: '#b8a3f5',
      fontSize: '13px',
      fontWeight: '500',
      textDecoration: 'underline',
      textUnderlineOffset: '3px',
      fontFamily: "'Inter', sans-serif",
    },

    // ── Hide unwanted Clerk chrome ────────────────────────────────────────────
    footerPages: { display: 'none' },
    badge: { display: 'none' },
    cardBox: { boxShadow: 'none', background: 'transparent', padding: '0' },
  },
};

// ─── CSS hover/focus effects injected via <style> tag ────────────────────────
// Clerk's appearance API only supports static JS objects (no :hover/:focus).
// We inject a minimal stylesheet for the interactive states.
const authStyles = `
  /* ── Social button hover ─────────────────────────────────────────────── */
  .cl-socialButtonsBlockButton:hover {
    background: #f5f5f5 !important;
    border-color: rgba(0,0,0,0.12) !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 14px rgba(0,0,0,0.18) !important;
  }
  .cl-socialButtonsBlockButton:active {
    background: #ebebeb !important;
    transform: translateY(0) !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.12) !important;
  }

  /* Force solid white background on ALL social buttons (kill glassmorphism) */
  .cl-socialButtonsBlockButton {
    background: #ffffff !important;
    background-color: #ffffff !important;
    background-image: none !important;
    border: 1px solid rgba(0,0,0,0.08) !important;
    color: #111111 !important;
    backdrop-filter: none !important;
    -webkit-backdrop-filter: none !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.18) !important;
  }

  /* Force dark text on button labels */
  .cl-socialButtonsBlockButtonText {
    color: #111111 !important;
  }

  /* Force GitHub button white (overrides Clerk's dark brand color) */
  [data-provider="github"],
  .cl-socialButtonsBlockButton__github {
    background: #ffffff !important;
    background-color: #ffffff !important;
    background-image: none !important;
    border: 1px solid rgba(0,0,0,0.08) !important;
    color: #111111 !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.18) !important;
  }

  /* Force GitHub ICON button white (variant: iconButton) */
  .cl-socialButtonsIconButton__github,
  [data-provider="github"].cl-socialButtonsIconButton {
    background: #ffffff !important;
    background-color: #ffffff !important;
    background-image: none !important;
    border: 1px solid rgba(0,0,0,0.08) !important;
    color: #111111 !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.18) !important;
  }
  .cl-socialButtonsIconButton__github .cl-socialButtonsIconButtonIcon,
  .cl-socialButtonsIconButton__github svg,
  .cl-socialButtonsIconButton__github .cl-socialButtonsBlockButtonText,
  .cl-socialButtonsIconButton__github .cl-socialButtonsBlockButton__text {
    color: #111111 !important;
    fill: #111111 !important;
  }

  /* Hide Apple button entirely (fallback; AuthPage observer also removes it) */
  [class*="apple"], [data-provider="apple"], [aria-label*="Apple"] { display: none !important; }

  /* Google button — same white pill style as GitHub */
  [data-provider="google"],
  .cl-socialButtonsBlockButton__google {
    background: #ffffff !important;
    background-color: #ffffff !important;
    background-image: none !important;
    border: 1px solid rgba(0,0,0,0.08) !important;
    color: #111111 !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.18) !important;
    backdrop-filter: none !important;
    -webkit-backdrop-filter: none !important;
  }
  [data-provider="google"] .cl-socialButtonsBlockButtonText,
  .cl-socialButtonsBlockButton__google .cl-socialButtonsBlockButtonText {
    color: #111111 !important;
  }
  [data-provider="google"]:hover,
  .cl-socialButtonsBlockButton__google:hover {
    background: #f5f5f5 !important;
    border-color: rgba(0,0,0,0.12) !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 14px rgba(0,0,0,0.18) !important;
  }
  [data-provider="google"]:active,
  .cl-socialButtonsBlockButton__google:active {
    background: #ebebeb !important;
    transform: translateY(0) !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.12) !important;
  }

  /* Force identical structure on ALL social buttons */
  .cl-socialButtonsBlockButton {
    height: 48px !important;
    min-height: 48px !important;
    padding: 0 16px !important;
    font-size: 14px !important;
    font-weight: 500 !important;
    font-family: 'Inter', sans-serif !important;
    letter-spacing: 0.01em !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    gap: 10px !important;
  }
  .cl-socialButtonsBlockButtonIcon,
  .cl-socialButtonsBlockButtonIconContainer,
  .cl-socialButtonsBlockButton img,
  .cl-socialButtonsBlockButton svg:not(.cl-spinner) {
    width: 20px !important;
    height: 20px !important;
    flex-shrink: 0 !important;
    object-fit: contain !important;
  }
  .cl-socialButtonsBlockButtonText {
    white-space: nowrap !important;
  }
  .cl-socialButtonsBlockButtonArrow { display: none !important; }

  /* ── Vector background (own layer so it can have opacity) ─────────────── */
  .auth-page-bg::before {
    content: '';
    position: absolute;
    inset: 0;
    background-image: url(/assets/Vector.png);
    background-repeat: no-repeat;
    background-position: center -50%;
    background-size: 100% auto;
    opacity: 0.5;
    pointer-events: none;
    z-index: 0;
  }

  /* ── Input hover & focus ──────────────────────────────────────────────── */
  .cl-formFieldInput:hover {
    border-color: rgba(167,139,250,0.28) !important;
  }
  .cl-formFieldInput:focus {
    border-color: rgba(167,139,250,0.60) !important;
    box-shadow: 0 0 0 3px rgba(109,40,217,0.16), 0 2px 8px rgba(109,40,217,0.10) !important;
    background: rgba(255,255,255,0.07) !important;
    outline: none !important;
  }
  .cl-formFieldInput::placeholder {
    color: rgba(196,181,253,0.35) !important;
  }

  /* ── CTA button hover glow ────────────────────────────────────────────── */
  .cl-formButtonPrimary:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 8px 28px rgba(139,92,246,0.45), 0 0 0 1px rgba(167,139,250,0.30) !important;
  }
  .cl-formButtonPrimary:active {
    transform: translateY(0) !important;
    box-shadow: 0 4px 12px rgba(139,92,246,0.25) !important;
  }
  .cl-formButtonPrimary:disabled {
    opacity: 0.45 !important;
    cursor: not-allowed !important;
    transform: none !important;
    box-shadow: none !important;
  }
  /* Hide any internal spinner SVG arrows in CTA button */
  .cl-formButtonPrimary__arrow { display: none !important; }

  /* ── Remove Clerk chrome (keep footer action / sign-up link) ──────────── */
  .cl-footer__poweredBy,
  .cl-poweredByClerk,
  .cl-footerPages { display: none !important; }

  /* Hide Last Used badge */
  .cl-badge, [class*="cl-badge"] { display: none !important; }

  /* ── Card & rootBox sizing ────────────────────────────────────────────── */
  .cl-rootBox { width: 100% !important; max-width: 460px !important; }
  .cl-card  { width: 100% !important; }

  /* Remove any Clerk-injected bottom padding on the card box */
  .cl-cardBox { padding-bottom: 0 !important; }

  /* ── Footer link hover ────────────────────────────────────────────────── */
  .cl-footerActionLink:hover {
    color: #c4b5fd !important;
    opacity: 1 !important;
  }
`;

// ─── Auth page wrapper component ─────────────────────────────────────────────
function AuthPage({ children }) {
  return (
    <>
      <style>{authStyles}</style>
      <div className="auth-page-bg" style={authPageStyle}>
        <div style={{ position: 'relative', zIndex: 1, width: '100%', display: 'flex', justifyContent: 'center' }}>
          {children}
        </div>
      </div>
    </>
  );
}

// ─── Route guards ─────────────────────────────────────────────────────────────
function DynamicTool() {
  const { toolId } = useParams();
  if (toolId === 'dns') return <DNSLookup />;
  if (toolId === 'whois') return <Whois />;
  if (toolId === 'webscan') return <WebAppScanner />;
  if (toolId === 'traceroute') return <Traceroute />;
  if (toolId === 'ssl') return <SSL />;
  return <GenericTool toolId={toolId} />;
}

function RequireAuth() {
  const { isLoaded, isSignedIn } = useAuth();

  if (!isLoaded) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <span className="tier-badge free">Loading…</span>
      </div>
    );
  }

  if (!isSignedIn) {
    return <Navigate to="/sign-in" replace />;
  }

  return (
    <TierProvider>
      <Navbar />
      <div className="app-main-layout flex">
        <Sidebar />
        <main className="flex-1 flex flex-col app-content-panel min-w-0">
          <Outlet />
        </main>
      </div>
      <UpgradeModal />
    </TierProvider>
  );
}

// ─── App ──────────────────────────────────────────────────────────────────────
export default function App() {
  return (
    <BrowserRouter>
      <div className="app-shell">
        <Routes>
          <Route
            path="/sign-in/*"
            element={
              <AuthPage>
                <SignIn
                  routing="path"
                  path="/sign-in"
                  signUpUrl="/sign-up"
                  fallbackRedirectUrl="/tools/portscanner"
                  appearance={clerkAppearance}
                />
              </AuthPage>
            }
          />
          <Route
            path="/sign-up/*"
            element={
              <AuthPage>
                <SignUp
                  routing="path"
                  path="/sign-up"
                  signInUrl="/sign-in"
                  fallbackRedirectUrl="/tools/portscanner"
                  appearance={clerkAppearance}
                />
              </AuthPage>
            }
          />

          <Route element={<RequireAuth />}>
            <Route path="/" element={<Navigate to="/tools/portscanner" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/tools/portscanner" element={<PortScanner />} />
            <Route path="/tools/webscan" element={<WebAppScanner />} />
            <Route path="/tools/:toolId" element={<DynamicTool />} />
            <Route path="/executive-report" element={<AIExecutiveReport />} />
          </Route>

          <Route path="*" element={<Navigate to="/sign-in" replace />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}
