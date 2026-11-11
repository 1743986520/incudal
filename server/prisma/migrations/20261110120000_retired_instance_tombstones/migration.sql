-- Retired host records retain unresolved accounting and cannot be silently
-- cascaded away by host, user, or instance removal.
BEGIN;

ALTER TABLE "instances" DROP CONSTRAINT "instances_deletion_billing_mode_check";
ALTER TABLE "instances" ADD CONSTRAINT "instances_deletion_billing_mode_check"
  CHECK ("deletion_billing_mode" IS NULL OR "deletion_billing_mode" IN
    ('user_destroy', 'privileged_delete', 'hourly_close', 'manual_retired_host'));

CREATE TABLE "retired_instance_tombstones" (
    "instance_id" INTEGER NOT NULL,
    "host_id" INTEGER NOT NULL,
    "source_digest" TEXT NOT NULL,
    "retirement_digest" TEXT NOT NULL,
    "original_billing_mode" TEXT,
    "remote_deletion_confirmed" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "retired_instance_tombstones_pkey" PRIMARY KEY ("instance_id")
);

CREATE INDEX "retired_instance_tombstones_host_id_idx" ON "retired_instance_tombstones"("host_id");

ALTER TABLE "retired_instance_tombstones" ADD CONSTRAINT "retired_instance_tombstones_instance_id_fkey"
  FOREIGN KEY ("instance_id") REFERENCES "instances"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "retired_instance_tombstones" ADD CONSTRAINT "retired_instance_tombstones_host_id_fkey"
  FOREIGN KEY ("host_id") REFERENCES "hosts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

COMMIT;
