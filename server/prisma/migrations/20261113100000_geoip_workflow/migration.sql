ALTER TYPE "ToolName" ADD VALUE IF NOT EXISTS 'ASN';
ALTER TYPE "ToolName" ADD VALUE IF NOT EXISTS 'GEOIP_BULK';
ALTER TYPE "ToolName" ADD VALUE IF NOT EXISTS 'GEOIP_CIDR';

CREATE TABLE "share_links" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "token" VARCHAR(64) NOT NULL,
  "run_id" UUID NOT NULL,
  "created_by" UUID NOT NULL,
  "expires_at" TIMESTAMPTZ(3) NOT NULL,
  "revoked_at" TIMESTAMPTZ(3),
  "redact_abuse_contact" BOOLEAN NOT NULL DEFAULT true,
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "share_links_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "share_links_token_key" ON "share_links"("token");
CREATE INDEX "share_links_created_by_created_at_idx" ON "share_links"("created_by", "created_at");
CREATE INDEX "share_links_expires_at_idx" ON "share_links"("expires_at");

ALTER TABLE "share_links"
  ADD CONSTRAINT "share_links_run_id_fkey"
  FOREIGN KEY ("run_id") REFERENCES "tool_runs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "share_links"
  ADD CONSTRAINT "share_links_created_by_fkey"
  FOREIGN KEY ("created_by") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
