-- API Key：受限实例控制凭证
-- 说明：本迁移必须自洽——全新数据库上 ApiKeyStatus 枚举此前从未被任何迁移创建，
-- 原迁移因此必然失败（P3009）。改为幂等写法：已存在的环境（如通过 db push 同步过
-- 的库）重复执行也不会冲突。

-- 1) 创建枚举（可能已存在）
DO $$ BEGIN
    CREATE TYPE "ApiKeyStatus" AS ENUM ('active', 'disabled');
EXCEPTION WHEN duplicate_object THEN null; END $$;

-- 2) 新建 api_keys 表
CREATE TABLE IF NOT EXISTS "api_keys" (
    "id" SERIAL PRIMARY KEY,
    "user_id" INTEGER NOT NULL,
    "name" TEXT,
    "key_hash" TEXT NOT NULL,
    "prefix" TEXT NOT NULL,
    "status" "ApiKeyStatus" NOT NULL DEFAULT 'active',
    "last_used_at" TIMESTAMP(3),
    "request_count" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateIndex
CREATE INDEX IF NOT EXISTS "api_keys_user_id_idx" ON "api_keys"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "api_keys_key_hash_key" ON "api_keys"("key_hash");

-- AddForeignKey（已存在时跳过）
DO $$ BEGIN
    ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN null; END $$;

-- 3) OperationType 枚举新增 api_key
ALTER TYPE "OperationType" ADD VALUE IF NOT EXISTS 'api_key';
