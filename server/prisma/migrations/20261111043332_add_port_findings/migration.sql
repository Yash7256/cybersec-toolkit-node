-- CreateTable
CREATE TABLE "port_findings" (
    "id" BIGSERIAL NOT NULL,
    "run_id" UUID NOT NULL,
    "port" INTEGER NOT NULL,
    "protocol" "Protocol" NOT NULL DEFAULT 'TCP',
    "state" "PortState" NOT NULL,
    "service" VARCHAR(100),
    "version" VARCHAR(255),
    "banner" VARCHAR(2000),
    "risk" "Severity",

    CONSTRAINT "port_findings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "port_findings_run_id_port_protocol_key" ON "port_findings"("run_id", "port", "protocol");

-- AddForeignKey
ALTER TABLE "port_findings" ADD CONSTRAINT "port_findings_run_id_fkey" FOREIGN KEY ("run_id") REFERENCES "tool_runs"("id") ON DELETE CASCADE ON UPDATE CASCADE;
