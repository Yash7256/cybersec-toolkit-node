ALTER TABLE "tool_runs" ADD COLUMN "cancel_requested_at" TIMESTAMPTZ(3);
ALTER TABLE "tool_runs" ADD COLUMN "quota_date" DATE;
ALTER TABLE "tool_runs" ADD COLUMN "quota_refunded" BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX "tool_runs_created_at_brin_idx" ON "tool_runs" USING BRIN ("created_at");
CREATE INDEX ix_tool_runs_user_active ON tool_runs (user_id) WHERE status IN ('QUEUED','RUNNING');
ALTER TABLE tool_runs ADD CONSTRAINT tool_runs_refund_needs_date CHECK (NOT quota_refunded OR quota_date IS NOT NULL);
