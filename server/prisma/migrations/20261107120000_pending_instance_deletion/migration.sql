ALTER TYPE "InstanceStatus" ADD VALUE IF NOT EXISTS 'deleting';
ALTER TABLE "instances"
  ADD COLUMN "deletion_original_status" "InstanceStatus",
  ADD COLUMN "deletion_requested_at" TIMESTAMP(3),
  ADD COLUMN "deletion_last_attempt_at" TIMESTAMP(3),
  ADD COLUMN "deletion_requested_by_id" INTEGER,
  ADD COLUMN "deletion_reason" TEXT;
CREATE INDEX "instances_status_deletion_last_attempt_at_idx" ON "instances"("status", "deletion_last_attempt_at");
