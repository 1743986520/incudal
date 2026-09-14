CREATE TYPE "TrafficBillingMode" AS ENUM ('package', 'usage');
CREATE TYPE "TrafficBillingRecordStatus" AS ENUM ('paid', 'pending');

ALTER TABLE "package_plans"
  ADD COLUMN "traffic_billing_mode" "TrafficBillingMode" NOT NULL DEFAULT 'package',
  ADD COLUMN "traffic_unit_price" DECIMAL(10,2) NOT NULL DEFAULT 0;

ALTER TABLE "instances"
  ADD COLUMN "traffic_billing_mode" "TrafficBillingMode" NOT NULL DEFAULT 'package',
  ADD COLUMN "traffic_unit_price" DECIMAL(10,2) NOT NULL DEFAULT 0,
  ADD COLUMN "traffic_settled_bytes" BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN "traffic_settled_cost" DECIMAL(10,2) NOT NULL DEFAULT 0,
  ADD COLUMN "next_traffic_billing_at" TIMESTAMP(3);

CREATE TABLE "traffic_billing_records" (
  "id" SERIAL NOT NULL,
  "instance_id" INTEGER NOT NULL,
  "user_id" INTEGER NOT NULL,
  "traffic_bytes" BIGINT NOT NULL,
  "unit_price" DECIMAL(10,2) NOT NULL,
  "amount" DECIMAL(10,2) NOT NULL,
  "status" "TrafficBillingRecordStatus" NOT NULL,
  "period_start" TIMESTAMP(3) NOT NULL,
  "period_end" TIMESTAMP(3) NOT NULL,
  "balance_log_id" INTEGER,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "traffic_billing_records_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "traffic_billing_records_instance_id_fkey" FOREIGN KEY ("instance_id") REFERENCES "instances"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "traffic_billing_records_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX "traffic_billing_records_instance_id_created_at_idx" ON "traffic_billing_records"("instance_id", "created_at" DESC);
CREATE INDEX "traffic_billing_records_user_id_created_at_idx" ON "traffic_billing_records"("user_id", "created_at" DESC);
CREATE INDEX "traffic_billing_records_status_idx" ON "traffic_billing_records"("status");
CREATE INDEX "instances_traffic_billing_mode_status_next_traffic_billing_at_idx" ON "instances"("traffic_billing_mode", "status", "next_traffic_billing_at");
