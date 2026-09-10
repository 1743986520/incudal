ALTER TABLE "instance_transfers"
  ADD COLUMN "claim_token" TEXT,
  ADD COLUMN "claim_expires_at" TIMESTAMP(3),
  ADD COLUMN "phase" TEXT,
  ADD COLUMN "old_incus_id" TEXT,
  ADD COLUMN "new_incus_id" TEXT,
  ADD COLUMN "instance_version" INTEGER,
  ADD COLUMN "cleanup_snapshot" JSONB,
  ADD COLUMN "refunded_at" TIMESTAMP(3);

CREATE UNIQUE INDEX "instance_transfers_claim_token_key"
ON "instance_transfers"("claim_token");

ALTER TABLE "balance_logs" ADD COLUMN "transfer_id" INTEGER;
CREATE UNIQUE INDEX "balance_logs_transfer_id_key" ON "balance_logs"("transfer_id");