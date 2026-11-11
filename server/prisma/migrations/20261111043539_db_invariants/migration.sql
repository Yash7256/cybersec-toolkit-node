-- ── CHECK constraints: the DB refuses nonsense even if app code is buggy ──
ALTER TABLE usage_counters ADD CONSTRAINT usage_counters_used_nonneg  CHECK (used >= 0);
ALTER TABLE tool_runs      ADD CONSTRAINT tool_runs_progress_range     CHECK (progress_pct BETWEEN 0 AND 100);
ALTER TABLE tool_runs      ADD CONSTRAINT tool_runs_attempt_nonneg     CHECK (attempt >= 0);
ALTER TABLE tool_runs      ADD CONSTRAINT tool_runs_time_order         CHECK (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at);
ALTER TABLE tool_runs      ADD CONSTRAINT tool_runs_finished_has_time  CHECK (status NOT IN ('COMPLETED','FAILED','CANCELLED','TIMED_OUT') OR finished_at IS NOT NULL);
ALTER TABLE port_findings  ADD CONSTRAINT port_findings_port_range     CHECK (port BETWEEN 1 AND 65535);
ALTER TABLE reports        ADD CONSTRAINT reports_size_nonneg          CHECK (size_bytes >= 0);
ALTER TABLE users          ADD CONSTRAINT users_email_lowercase        CHECK (email IS NULL OR email = lower(email));
ALTER TABLE cves           ADD CONSTRAINT cves_id_format               CHECK (id ~ '^CVE-[0-9]{4}-[0-9]{4,}$');

-- ── Partial indexes (tiny, because they only cover live jobs) ──
CREATE INDEX ix_tool_runs_running_heartbeat ON tool_runs (heartbeat_at) WHERE status = 'RUNNING';        -- Q6 reaper
CREATE INDEX ix_tool_runs_active            ON tool_runs (status, queued_at) WHERE status IN ('QUEUED','RUNNING'); -- Q7

-- ── Row-Level Security: deny-by-default for Supabase's public API ──
ALTER TABLE users              ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_counters     ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_runs          ENABLE ROW LEVEL SECURITY;
ALTER TABLE run_results        ENABLE ROW LEVEL SECURITY;
ALTER TABLE port_findings      ENABLE ROW LEVEL SECURITY;
ALTER TABLE cves               ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_cves       ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_cve_lookups ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports            ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_events     ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs         ENABLE ROW LEVEL SECURITY;
-- No policies on purpose. The server connects as the owner role (bypasses RLS).
-- Plain local Postgres (non-Supabase) also accepts this; harmless there.

-- ── Autovacuum tuning for the churn-heavy table (status updates create dead tuples) ──
ALTER TABLE tool_runs SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);
ALTER TABLE usage_counters SET (autovacuum_vacuum_scale_factor = 0.05, fillfactor = 85);  -- HOT updates
