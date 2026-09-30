ALTER TABLE "hourly_billing_accounts"
  ADD COLUMN "pricing_snapshot" JSONB;

-- Never silently turn an orphaned legacy account into a zero-priced account.
-- The two known billing sources are the linked legacy version or the package
-- plan (directly linked on the account or retained by the instance).
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM "hourly_billing_accounts" AS account
    JOIN "instances" AS instance ON instance."id" = account."instance_id"
    LEFT JOIN "package_plans" AS plan
      ON plan."id" = COALESCE(account."package_plan_id", instance."package_plan_id")
    LEFT JOIN "hourly_pricing_versions" AS legacy
      ON legacy."id" = account."pricing_version_id"
    WHERE plan."id" IS NULL AND legacy."id" IS NULL
  ) THEN
    RAISE EXCEPTION 'Cannot snapshot hourly pricing: one or more accounts have no pricing plan or legacy pricing version';
  END IF;
END $$;

-- Freeze the exact terms already in effect for every live hourly account.
-- Prefer the legacy version linked to the account (it may be older than the
-- current plan); newer plan-based accounts fall back to their source plan.
WITH "pricing_sources" AS (
  SELECT
    account."id",
    jsonb_build_object(
      'cpuUnitPercent', COALESCE(legacy."cpu_unit_percent", plan."hourly_cpu_unit_percent", 5),
      'memoryUnitMb', COALESCE(legacy."memory_unit_mb", plan."hourly_memory_unit_mb", 64),
      'diskUnitMb', COALESCE(legacy."disk_unit_mb", plan."hourly_disk_unit_mb", 512),
      'minCpu', COALESCE(legacy."min_cpu", plan."hourly_min_cpu", 15),
      'minMemoryMb', COALESCE(legacy."min_memory_mb", plan."hourly_min_memory_mb", 128),
      'minDiskMb', COALESCE(legacy."min_disk_mb", plan."hourly_min_disk_mb", 512),
      'cpuPricePerUnit', COALESCE(legacy."cpu_price_per_unit", plan."hourly_cpu_price_per_unit")::text,
      'memoryPricePerUnit', COALESCE(legacy."memory_price_per_unit", plan."hourly_memory_price_per_unit")::text,
      'diskPricePerUnit', COALESCE(legacy."disk_price_per_unit", plan."hourly_disk_price_per_unit")::text,
      'reserveQuantum', COALESCE(legacy."reserve_quantum", plan."hourly_reserve_quantum", 0.01)::text
  ) AS "snapshot"
  FROM "hourly_billing_accounts" AS account
  JOIN "instances" AS instance ON instance."id" = account."instance_id"
  LEFT JOIN "package_plans" AS plan
    ON plan."id" = COALESCE(account."package_plan_id", instance."package_plan_id")
  LEFT JOIN "hourly_pricing_versions" AS legacy
    ON legacy."id" = account."pricing_version_id"
)
UPDATE "hourly_billing_accounts" AS account
SET "pricing_snapshot" = pricing_sources."snapshot"
FROM "pricing_sources"
WHERE account."id" = pricing_sources."id";

ALTER TABLE "hourly_billing_accounts"
  ALTER COLUMN "pricing_snapshot" SET NOT NULL;
