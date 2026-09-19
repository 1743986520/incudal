-- AlterTable
-- 先带默认值以回填已有行，随后删除默认值以匹配 Prisma 对 @updatedAt 列的期望状态
ALTER TABLE "aff_bindings" ADD COLUMN     "supersedes_official_coupon" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE "aff_bindings" ALTER COLUMN "updated_at" DROP DEFAULT;
