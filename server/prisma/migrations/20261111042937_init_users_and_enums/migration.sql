-- CreateEnum
CREATE TYPE "UserTier" AS ENUM ('FREE', 'PAID');

-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('USER', 'ADMIN');

-- CreateEnum
CREATE TYPE "ToolName" AS ENUM ('PORT_SCAN', 'WEBAPP_SCAN', 'DNS', 'WHOIS', 'PING', 'TRACEROUTE', 'SSL', 'HTTP_HEADERS', 'SUBDOMAIN', 'GEOIP');

-- CreateEnum
CREATE TYPE "RunStatus" AS ENUM ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT');

-- CreateEnum
CREATE TYPE "Protocol" AS ENUM ('TCP', 'UDP');

-- CreateEnum
CREATE TYPE "PortState" AS ENUM ('OPEN', 'CLOSED', 'FILTERED', 'OPEN_FILTERED');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "ReportFormat" AS ENUM ('JSON', 'CSV', 'PDF');

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "clerk_user_id" VARCHAR(64) NOT NULL,
    "email" VARCHAR(320),
    "tier" "UserTier" NOT NULL DEFAULT 'FREE',
    "role" "UserRole" NOT NULL DEFAULT 'USER',
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "deleted_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_clerk_user_id_key" ON "users"("clerk_user_id");

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");
