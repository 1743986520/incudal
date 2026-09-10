ALTER TABLE "instance_billing_records"
ADD COLUMN "transfer_id" INTEGER;

CREATE UNIQUE INDEX "instance_billing_records_transfer_id_key"
ON "instance_billing_records"("transfer_id");

ALTER TABLE "instance_billing_records"
ADD CONSTRAINT "instance_billing_records_transfer_id_fkey"
FOREIGN KEY ("transfer_id") REFERENCES "instance_transfers"("id")
ON DELETE SET NULL ON UPDATE CASCADE;
