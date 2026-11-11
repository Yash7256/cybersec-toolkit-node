-- CreateTable
CREATE TABLE "usage_counters" (
    "user_id" UUID NOT NULL,
    "tool" "ToolName" NOT NULL,
    "usage_date" DATE NOT NULL,
    "used" INTEGER NOT NULL DEFAULT 0,
    "updated_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "usage_counters_pkey" PRIMARY KEY ("user_id","tool","usage_date")
);

-- CreateIndex
CREATE INDEX "usage_counters_usage_date_idx" ON "usage_counters"("usage_date");

-- AddForeignKey
ALTER TABLE "usage_counters" ADD CONSTRAINT "usage_counters_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
