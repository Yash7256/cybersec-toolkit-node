-- CreateTable
CREATE TABLE "tool_runs" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "tool" "ToolName" NOT NULL,
    "target" VARCHAR(255) NOT NULL,
    "target_key" VARCHAR(255) NOT NULL,
    "status" "RunStatus" NOT NULL DEFAULT 'QUEUED',
    "options" JSONB,
    "summary" JSONB,
    "progress_pct" SMALLINT NOT NULL DEFAULT 0,
    "attempt" SMALLINT NOT NULL DEFAULT 0,
    "worker_id" VARCHAR(100),
    "heartbeat_at" TIMESTAMPTZ(3),
    "error_code" VARCHAR(60),
    "error_message" VARCHAR(1000),
    "queued_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "started_at" TIMESTAMPTZ(3),
    "finished_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tool_runs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "run_results" (
    "run_id" UUID NOT NULL,
    "data" JSONB NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "run_results_pkey" PRIMARY KEY ("run_id")
);

-- CreateIndex
CREATE INDEX "tool_runs_user_id_created_at_id_idx" ON "tool_runs"("user_id", "created_at" DESC, "id" DESC);

-- CreateIndex
CREATE INDEX "tool_runs_user_id_tool_created_at_idx" ON "tool_runs"("user_id", "tool", "created_at" DESC);

-- CreateIndex
CREATE INDEX "tool_runs_user_id_tool_target_key_created_at_idx" ON "tool_runs"("user_id", "tool", "target_key", "created_at" DESC);

-- AddForeignKey
ALTER TABLE "tool_runs" ADD CONSTRAINT "tool_runs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "run_results" ADD CONSTRAINT "run_results_run_id_fkey" FOREIGN KEY ("run_id") REFERENCES "tool_runs"("id") ON DELETE CASCADE ON UPDATE CASCADE;
