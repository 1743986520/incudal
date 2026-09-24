ALTER TABLE "package_plans"
  ADD COLUMN "hourly_min_cpu" INTEGER NOT NULL DEFAULT 15,
  ADD COLUMN "hourly_cpu_unit_percent" INTEGER NOT NULL DEFAULT 5,
  ADD COLUMN "hourly_cpu_price_per_unit" DECIMAL(20,8) NOT NULL DEFAULT 0,
  ADD COLUMN "hourly_min_memory_mb" INTEGER NOT NULL DEFAULT 128,
  ADD COLUMN "hourly_memory_unit_mb" INTEGER NOT NULL DEFAULT 64,
  ADD COLUMN "hourly_memory_price_per_unit" DECIMAL(20,8) NOT NULL DEFAULT 0,
  ADD COLUMN "hourly_min_disk_mb" INTEGER NOT NULL DEFAULT 512,
  ADD COLUMN "hourly_disk_unit_mb" INTEGER NOT NULL DEFAULT 512,
  ADD COLUMN "hourly_disk_price_per_unit" DECIMAL(20,8) NOT NULL DEFAULT 0,
  ADD COLUMN "hourly_reserve_quantum" DECIMAL(20,8) NOT NULL DEFAULT 0.01;

ALTER TABLE "hourly_billing_accounts"
  ADD COLUMN "package_plan_id" INTEGER,
  ALTER COLUMN "pricing_version_id" DROP NOT NULL;

ALTER TABLE "hourly_billing_records"
  ADD COLUMN "package_plan_id" INTEGER,
  ALTER COLUMN "pricing_version_id" DROP NOT NULL;

-- Preserve the currently active global price for hourly plans that were created
-- before pricing became a property of each package plan.
UPDATE "package_plans" AS plan
SET
  "hourly_min_cpu" = pricing."min_cpu",
  "hourly_cpu_unit_percent" = pricing."cpu_unit_percent",
  "hourly_cpu_price_per_unit" = pricing."cpu_price_per_unit",
  "hourly_min_memory_mb" = pricing."min_memory_mb",
  "hourly_memory_unit_mb" = pricing."memory_unit_mb",
  "hourly_memory_price_per_unit" = pricing."memory_price_per_unit",
  "hourly_min_disk_mb" = pricing."min_disk_mb",
  "hourly_disk_unit_mb" = pricing."disk_unit_mb",
  "hourly_disk_price_per_unit" = pricing."disk_price_per_unit",
  "hourly_reserve_quantum" = pricing."reserve_quantum"
FROM (
  SELECT *
  FROM "hourly_pricing_versions"
  WHERE "enabled" = TRUE
  ORDER BY "effective_at" DESC, "version" DESC
  LIMIT 1
) AS pricing
WHERE plan."billing_mode" = 'hourly';

UPDATE "hourly_billing_accounts" AS account
SET "package_plan_id" = instance."package_plan_id"
FROM "instances" AS instance
WHERE instance."id" = account."instance_id"
  AND instance."package_plan_id" IS NOT NULL;

UPDATE "hourly_billing_records" AS record
SET "package_plan_id" = instance."package_plan_id"
FROM "instances" AS instance
WHERE instance."id" = record."instance_id"
  AND instance."package_plan_id" IS NOT NULL;

ALTER TABLE "hourly_billing_accounts"
  ADD CONSTRAINT "hourly_billing_accounts_package_plan_id_fkey"
  FOREIGN KEY ("package_plan_id") REFERENCES "package_plans"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "hourly_billing_records"
  ADD CONSTRAINT "hourly_billing_records_package_plan_id_fkey"
  FOREIGN KEY ("package_plan_id") REFERENCES "package_plans"("id") ON DELETE SET NULL ON UPDATE CASCADE;

CREATE INDEX "hourly_billing_accounts_package_plan_id_idx" ON "hourly_billing_accounts"("package_plan_id");
CREATE INDEX "hourly_billing_records_package_plan_id_idx" ON "hourly_billing_records"("package_plan_id");
