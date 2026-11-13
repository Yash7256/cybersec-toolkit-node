CREATE TYPE "AuthorizationMethod" AS ENUM ('ATTESTATION');
CREATE TYPE "AuthorizationStatus" AS ENUM ('APPROVED', 'REVOKED');

CREATE TABLE "target_authorizations" (
  "id" UUID NOT NULL,
  "user_id" UUID NOT NULL,
  "registrable_domain" VARCHAR(253) NOT NULL,
  "method" "AuthorizationMethod" NOT NULL DEFAULT 'ATTESTATION',
  "status" "AuthorizationStatus" NOT NULL DEFAULT 'APPROVED',
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "revoked_at" TIMESTAMPTZ(3),
  CONSTRAINT "target_authorizations_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "target_authorizations_user_id_registrable_domain_key" ON "target_authorizations"("user_id", "registrable_domain");
CREATE INDEX "target_authorizations_registrable_domain_status_idx" ON "target_authorizations"("registrable_domain", "status");
ALTER TABLE "target_authorizations" ADD CONSTRAINT "target_authorizations_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "target_authorizations" ENABLE ROW LEVEL SECURITY;
