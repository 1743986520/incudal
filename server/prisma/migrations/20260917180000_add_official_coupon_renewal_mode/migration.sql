-- CreateEnum
CREATE TYPE "OfficialCouponRenewalMode" AS ENUM ('purchase_only', 'limited', 'recurring');

-- CreateEnum
CREATE TYPE "OfficialCouponUsageType" AS ENUM ('purchase', 'renewal');

-- AlterTable
ALTER TABLE "official_coupons" ADD COLUMN     "discounted_charge_limit" INTEGER,
ADD COLUMN     "renewal_mode" "OfficialCouponRenewalMode" NOT NULL DEFAULT 'purchase_only';

-- AlterTable
ALTER TABLE "official_coupon_usages" ADD COLUMN     "type" "OfficialCouponUsageType" NOT NULL DEFAULT 'purchase';
