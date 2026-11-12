-- 敏感操作二次确认从「验证码」改为「邮件确认链接」：
-- 新增 operation_confirms（一次性 token，1 小时有效，点击即执行），
-- 移除旧的 operation_verifications 验证码表与 VerificationChannel 枚举。

-- CreateTable
CREATE TABLE "operation_confirms" (
    "id" SERIAL PRIMARY KEY,
    "user_id" INTEGER NOT NULL,
    "operation_type" "OperationType" NOT NULL,
    "resource_id" INTEGER,
    "token_hash" TEXT NOT NULL,
    "payload" JSONB,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "consumed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateIndex
CREATE INDEX "operation_confirms_user_id_operation_type_resource_id_idx" ON "operation_confirms"("user_id", "operation_type", "resource_id");

-- CreateIndex
CREATE INDEX "operation_confirms_expires_at_idx" ON "operation_confirms"("expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "operation_confirms_token_hash_key" ON "operation_confirms"("token_hash");

-- AddForeignKey
ALTER TABLE "operation_confirms" ADD CONSTRAINT "operation_confirms_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- DropTable
DROP TABLE "operation_verifications";

-- DropEnum
DROP TYPE "VerificationChannel";
