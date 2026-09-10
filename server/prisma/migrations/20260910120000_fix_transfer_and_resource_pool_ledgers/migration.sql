-- One transfer legitimately produces multiple balance log entries (debit and
-- refund). The old unique index made rejection/cancellation fail after a fee
-- had already been charged.
DROP INDEX IF EXISTS "balance_logs_transfer_id_key";
CREATE INDEX IF NOT EXISTS "balance_logs_transfer_id_idx"
  ON "balance_logs"("transfer_id");

-- Keep failed resource-pool applications distinguishable from grants.
ALTER TYPE "ResourcePoolAction" ADD VALUE IF NOT EXISTS 'refund';
