-- CreateEnum
CREATE TYPE "OfficialCouponScope" AS ENUM ('all', 'official_only', 'hosted_only');

-- CreateTable
CREATE TABLE "official_coupons" (
    "id" SERIAL NOT NULL,
    "code" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "remark" TEXT,
    "discount_rate" DECIMAL(5,4) NOT NULL,
    "scope" "OfficialCouponScope" NOT NULL DEFAULT 'all',
    "reusable" BOOLEAN NOT NULL DEFAULT false,
    "max_uses_per_user" INTEGER,
    "total_usage_limit" INTEGER,
    "used_count" INTEGER NOT NULL DEFAULT 0,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "starts_at" TIMESTAMP(3),
    "expires_at" TIMESTAMP(3),
    "created_by_id" INTEGER,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "official_coupons_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "official_coupon_usages" (
    "id" SERIAL NOT NULL,
    "coupon_id" INTEGER NOT NULL,
    "user_id" INTEGER NOT NULL,
    "instance_id" INTEGER,
    "original_price" DECIMAL(10,2) NOT NULL,
    "discount_amount" DECIMAL(10,2) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "official_coupon_usages_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "official_coupons_code_key" ON "official_coupons"("code");

-- CreateIndex
CREATE INDEX "official_coupons_enabled_idx" ON "official_coupons"("enabled");

-- CreateIndex
CREATE INDEX "official_coupons_scope_idx" ON "official_coupons"("scope");

-- CreateIndex
CREATE INDEX "official_coupons_created_at_idx" ON "official_coupons"("created_at" DESC);

-- CreateIndex
CREATE INDEX "official_coupon_usages_coupon_id_user_id_idx" ON "official_coupon_usages"("coupon_id", "user_id");

-- CreateIndex
CREATE INDEX "official_coupon_usages_coupon_id_created_at_idx" ON "official_coupon_usages"("coupon_id", "created_at" DESC);

-- CreateIndex
CREATE INDEX "official_coupon_usages_user_id_idx" ON "official_coupon_usages"("user_id");

-- CreateIndex
CREATE INDEX "official_coupon_usages_instance_id_idx" ON "official_coupon_usages"("instance_id");

-- AddForeignKey
ALTER TABLE "official_coupons" ADD CONSTRAINT "official_coupons_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "official_coupon_usages" ADD CONSTRAINT "official_coupon_usages_coupon_id_fkey" FOREIGN KEY ("coupon_id") REFERENCES "official_coupons"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "official_coupon_usages" ADD CONSTRAINT "official_coupon_usages_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "official_coupon_usages" ADD CONSTRAINT "official_coupon_usages_instance_id_fkey" FOREIGN KEY ("instance_id") REFERENCES "instances"("id") ON DELETE SET NULL ON UPDATE CASCADE;
