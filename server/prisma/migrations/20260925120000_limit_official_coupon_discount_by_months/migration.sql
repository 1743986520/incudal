-- Track the actual number of discounted months for each coupon usage.
-- Existing usage rows are backfilled from the billing record created in the
-- same purchase/renewal transaction whenever that record is available.
ALTER TABLE "official_coupon_usages"
  ADD COLUMN "discounted_months" INTEGER NOT NULL DEFAULT 1;

UPDATE "official_coupon_usages" AS usage
SET "discounted_months" = COALESCE(
  (
    SELECT billing."months"
    FROM "instance_billing_records" AS billing
    WHERE billing."instance_id" = usage."instance_id"
      AND (
        (usage."type" = 'purchase' AND billing."type" = 'newPurchase')
        OR (usage."type" = 'renewal' AND billing."type" = 'renew')
      )
      AND billing."created_at" <= usage."created_at"
    ORDER BY billing."created_at" DESC, billing."id" DESC
    LIMIT 1
  ),
  1
);

ALTER TABLE "official_coupon_usages"
  ADD CONSTRAINT "official_coupon_usages_discounted_months_positive"
  CHECK ("discounted_months" > 0);
