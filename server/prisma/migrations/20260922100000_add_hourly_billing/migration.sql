CREATE TYPE "InstanceBillingMode" AS ENUM ('package', 'hourly');
CREATE TYPE "HourlyBillingStatus" AS ENUM ('active', 'paused', 'suspended', 'closed');
CREATE TYPE "HourlyBillingRecordStatus" AS ENUM ('paid', 'pending');

ALTER TYPE "BalanceLogType" ADD VALUE 'hourly_reserve';
ALTER TYPE "BalanceLogType" ADD VALUE 'hourly_release';
ALTER TYPE "BalanceLogType" ADD VALUE 'hourly_consume';
ALTER TYPE "HostingActionType" ADD VALUE 'hourly';

ALTER TABLE "users"
  ALTER COLUMN "balance" TYPE DECIMAL(20,8) USING "balance"::numeric,
  ALTER COLUMN "hosting_balance" TYPE DECIMAL(20,8) USING "hosting_balance"::numeric,
  ADD COLUMN "hourly_reserved_balance" DECIMAL(20,8) NOT NULL DEFAULT 0;

ALTER TABLE "balance_logs"
  ALTER COLUMN "amount" TYPE DECIMAL(20,8) USING "amount"::numeric,
  ALTER COLUMN "balance_before" TYPE DECIMAL(20,8) USING "balance_before"::numeric,
  ALTER COLUMN "balance_after" TYPE DECIMAL(20,8) USING "balance_after"::numeric;

ALTER TABLE "hosting_balance_logs"
  ALTER COLUMN "amount" TYPE DECIMAL(20,8) USING "amount"::numeric;

ALTER TABLE "hosts"
  ADD COLUMN "hourly_billing_enabled" BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE "instances"
  ADD COLUMN "billing_mode" "InstanceBillingMode" NOT NULL DEFAULT 'package';

CREATE TABLE "hourly_pricing_versions" (
  "id" SERIAL NOT NULL,
  "version" INTEGER NOT NULL,
  "enabled" BOOLEAN NOT NULL DEFAULT false,
  "cpu_unit_percent" INTEGER NOT NULL DEFAULT 5,
  "memory_unit_mb" INTEGER NOT NULL DEFAULT 64,
  "disk_unit_mb" INTEGER NOT NULL DEFAULT 512,
  "min_cpu" INTEGER NOT NULL DEFAULT 15,
  "min_memory_mb" INTEGER NOT NULL DEFAULT 128,
  "min_disk_mb" INTEGER NOT NULL DEFAULT 512,
  "cpu_price_per_unit" DECIMAL(20,8) NOT NULL,
  "memory_price_per_unit" DECIMAL(20,8) NOT NULL,
  "disk_price_per_unit" DECIMAL(20,8) NOT NULL,
  "reserve_quantum" DECIMAL(20,8) NOT NULL DEFAULT 0.01,
  "traffic_unit_price" DECIMAL(10,2) NOT NULL DEFAULT 0,
  "traffic_included_bytes" BIGINT NOT NULL DEFAULT 0,
  "effective_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "created_by" INTEGER,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "hourly_pricing_versions_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "hourly_pricing_versions_version_key" UNIQUE ("version"),
  CONSTRAINT "hourly_pricing_versions_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE "hourly_billing_accounts" (
  "id" SERIAL NOT NULL,
  "instance_id" INTEGER NOT NULL,
  "pricing_version_id" INTEGER NOT NULL,
  "last_settled_at" TIMESTAMP(3) NOT NULL,
  "next_settlement_at" TIMESTAMP(3),
  "prepaid_balance" DECIMAL(20,8) NOT NULL DEFAULT 0,
  "total_cost" DECIMAL(20,8) NOT NULL DEFAULT 0,
  "total_reserved" DECIMAL(20,8) NOT NULL DEFAULT 0,
  "total_released" DECIMAL(20,8) NOT NULL DEFAULT 0,
  "outstanding_amount" DECIMAL(20,8) NOT NULL DEFAULT 0,
  "status" "HourlyBillingStatus" NOT NULL DEFAULT 'paused',
  "version" INTEGER NOT NULL DEFAULT 0,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "hourly_billing_accounts_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "hourly_billing_accounts_instance_id_key" UNIQUE ("instance_id"),
  CONSTRAINT "hourly_billing_accounts_instance_id_fkey" FOREIGN KEY ("instance_id") REFERENCES "instances"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "hourly_billing_accounts_pricing_version_id_fkey" FOREIGN KEY ("pricing_version_id") REFERENCES "hourly_pricing_versions"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE "hourly_billing_records" (
  "id" SERIAL NOT NULL,
  "settlement_key" TEXT NOT NULL,
  "account_id" INTEGER NOT NULL,
  "instance_id" INTEGER NOT NULL,
  "user_id" INTEGER NOT NULL,
  "pricing_version_id" INTEGER NOT NULL,
  "period_start" TIMESTAMP(3) NOT NULL,
  "period_end" TIMESTAMP(3) NOT NULL,
  "active_seconds" INTEGER NOT NULL,
  "cpu" INTEGER NOT NULL,
  "memory" INTEGER NOT NULL,
  "disk" INTEGER NOT NULL,
  "cpu_amount" DECIMAL(20,8) NOT NULL,
  "memory_amount" DECIMAL(20,8) NOT NULL,
  "disk_amount" DECIMAL(20,8) NOT NULL,
  "actual_amount" DECIMAL(20,8) NOT NULL,
  "reserve_amount" DECIMAL(20,8) NOT NULL DEFAULT 0,
  "release_amount" DECIMAL(20,8) NOT NULL DEFAULT 0,
  "status" "HourlyBillingRecordStatus" NOT NULL DEFAULT 'paid',
  "balance_log_id" INTEGER,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "hourly_billing_records_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "hourly_billing_records_settlement_key_key" UNIQUE ("settlement_key"),
  CONSTRAINT "hourly_billing_records_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "hourly_billing_accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "hourly_billing_records_instance_id_fkey" FOREIGN KEY ("instance_id") REFERENCES "instances"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "hourly_billing_records_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "hourly_billing_records_pricing_version_id_fkey" FOREIGN KEY ("pricing_version_id") REFERENCES "hourly_pricing_versions"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE INDEX "hourly_pricing_versions_enabled_effective_at_idx" ON "hourly_pricing_versions"("enabled", "effective_at");
CREATE INDEX "hourly_billing_accounts_status_next_settlement_at_idx" ON "hourly_billing_accounts"("status", "next_settlement_at");
CREATE INDEX "hourly_billing_records_instance_id_created_at_idx" ON "hourly_billing_records"("instance_id", "created_at" DESC);
CREATE INDEX "hourly_billing_records_user_id_created_at_idx" ON "hourly_billing_records"("user_id", "created_at" DESC);
CREATE INDEX "hourly_billing_records_status_idx" ON "hourly_billing_records"("status");
CREATE INDEX "instances_billing_mode_status_idx" ON "instances"("billing_mode", "status");

ALTER TABLE "instances"
  ADD CONSTRAINT "instances_billing_mode_hourly_account_check"
  CHECK ("billing_mode" = 'package' OR ("package_id" IS NULL AND "package_plan_id" IS NULL));
