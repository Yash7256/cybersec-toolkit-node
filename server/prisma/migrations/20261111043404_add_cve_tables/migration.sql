-- CreateTable
CREATE TABLE "cves" (
    "id" VARCHAR(20) NOT NULL,
    "cvss_score" DECIMAL(3,1),
    "severity" "Severity",
    "summary" TEXT,
    "data" JSONB NOT NULL,
    "published_at" TIMESTAMPTZ(3),
    "fetched_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "cves_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "finding_cves" (
    "finding_id" BIGINT NOT NULL,
    "cve_id" VARCHAR(20) NOT NULL,

    CONSTRAINT "finding_cves_pkey" PRIMARY KEY ("finding_id","cve_id")
);

-- CreateTable
CREATE TABLE "service_cve_lookups" (
    "cache_key" CHAR(64) NOT NULL,
    "service" VARCHAR(100) NOT NULL,
    "version" VARCHAR(100) NOT NULL,
    "cve_ids" TEXT[],
    "fetched_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "service_cve_lookups_pkey" PRIMARY KEY ("cache_key")
);

-- CreateIndex
CREATE INDEX "cves_expires_at_idx" ON "cves"("expires_at");

-- CreateIndex
CREATE INDEX "finding_cves_cve_id_idx" ON "finding_cves"("cve_id");

-- CreateIndex
CREATE INDEX "service_cve_lookups_expires_at_idx" ON "service_cve_lookups"("expires_at");

-- AddForeignKey
ALTER TABLE "finding_cves" ADD CONSTRAINT "finding_cves_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "port_findings"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_cves" ADD CONSTRAINT "finding_cves_cve_id_fkey" FOREIGN KEY ("cve_id") REFERENCES "cves"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
