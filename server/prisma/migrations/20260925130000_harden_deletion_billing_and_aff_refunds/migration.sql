-- Keep deletion billing recoverable after the external Incus deletion has
-- succeeded but the balance/hosting settlement transaction has failed.
ALTER TABLE "instances"
  ADD COLUMN "deletion_billing_pending" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "deletion_remote_deleted" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "deletion_billing_mode" TEXT,
  ADD COLUMN "deletion_refundable_value" DECIMAL(10,2),
  ADD COLUMN "deletion_fee_waiver" BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE "instances"
  ADD CONSTRAINT "instances_deletion_billing_mode_check"
  CHECK ("deletion_billing_mode" IS NULL OR "deletion_billing_mode" IN ('user_destroy', 'privileged_delete', 'hourly_close'));

ALTER TYPE "AffLogType" ADD VALUE 'refund';
