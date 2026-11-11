-- CreateTable
CREATE TABLE "reports" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "run_id" UUID NOT NULL,
    "format" "ReportFormat" NOT NULL,
    "storage_key" VARCHAR(500) NOT NULL,
    "size_bytes" INTEGER NOT NULL,
    "sha256" CHAR(64) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3),

    CONSTRAINT "reports_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "reports_user_id_created_at_idx" ON "reports"("user_id", "created_at" DESC);

-- CreateIndex
CREATE INDEX "reports_run_id_idx" ON "reports"("run_id");

-- AddForeignKey
ALTER TABLE "reports" ADD CONSTRAINT "reports_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reports" ADD CONSTRAINT "reports_run_id_fkey" FOREIGN KEY ("run_id") REFERENCES "tool_runs"("id") ON DELETE CASCADE ON UPDATE CASCADE;
