ALTER TABLE "package_plans"
  ADD COLUMN "billing_mode" "InstanceBillingMode" NOT NULL DEFAULT 'package';

ALTER TABLE "instances"
  DROP CONSTRAINT "instances_billing_mode_hourly_account_check";

ALTER TABLE "instances"
  ADD CONSTRAINT "instances_billing_mode_hourly_account_check"
  CHECK (
    "billing_mode" = 'package'
    OR ("billing_mode" = 'hourly' AND "package_id" IS NOT NULL AND "package_plan_id" IS NOT NULL)
    -- Keep already-created standalone hourly instances readable during migration;
    -- all new hourly instances are created through a package plan.
    OR ("billing_mode" = 'hourly' AND "package_id" IS NULL AND "package_plan_id" IS NULL)
  );
