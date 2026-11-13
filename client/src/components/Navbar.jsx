import { useNavigate } from 'react-router-dom';
import { useAuth, useUser } from '@clerk/react';
import { useTier } from '../context/TierContext';

/**
 * Application navbar with Clerk sign-in/out and tier badge.
 */
export default function Navbar() {
  const navigate = useNavigate();
  const { isLoaded, isSignedIn, signOut } = useAuth();
  const { user } = useUser();
  const { limit, unlimited, loading } = useTier();

  const badgeClass = unlimited ? 'tier-badge paid' : 'tier-badge free';
  const badgeLabel = unlimited ? 'PRO' : `FREE · ${limit}/tool/day`;
  const badgeTitle = unlimited ? 'Unlimited access' : `Free tier: ${limit} uses per tool per day`;

  if (!isLoaded) {
    return (
      <header className="app-navbar fixed top-0 left-0 right-0 z-50 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <img src="/assets/logo.png" alt="CyberSec" className="brand-logo w-auto object-contain" />
        </div>
        <div className="flex items-center gap-3 sm:gap-4">
          <span className="tier-badge free">Loading…</span>
        </div>
      </header>
    );
  }

  return (
    <header className="app-navbar fixed top-0 left-0 right-0 z-50 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <img src="/assets/logo.png" alt="CyberSec" className="brand-logo w-auto object-contain" />
      </div>

      <div className="flex items-center gap-3 sm:gap-4">
        {!loading && (
          <span className={badgeClass} title={badgeTitle}>
            {badgeLabel}
          </span>
        )}

        {isSignedIn ? (
          <>
            <button
              onClick={() => navigate('/dashboard')}
              className="text-sm hidden sm:block transition hover:underline"
              style={{ color: '#c4b5fd', background: 'none', border: 'none', padding: 0, cursor: 'pointer' }}
            >
              {user.fullName || user.primaryEmailAddress?.emailAddress || 'Signed in'}
            </button>
            <button
              onClick={() => signOut()}
              className="btn-secondary text-sm px-3 py-1.5"
            >
              Sign Out
            </button>
          </>
        ) : (
          <button
            onClick={() => navigate('/sign-in')}
            className="btn-primary text-sm px-3 py-1.5"
          >
            Sign In
          </button>
        )}
      </div>
    </header>
  );
}
