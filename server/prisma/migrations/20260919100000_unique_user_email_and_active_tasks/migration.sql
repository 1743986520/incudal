-- 审查项 P2-10：注册邮箱存在"查询-写入"竞态，缺少数据库级唯一约束。
-- 为大小写不敏感的唯一性创建函数索引（email 允许为 NULL，部分索引跳过空值）。
-- 清理历史重复数据前，先把将被修改的行写入备份表（*_migration_backup_20260919_*），
-- 迁移可通过备份表回滚：email 从备份表还原；任务状态/错误/结束时间同理。

CREATE TABLE "_migration_backup_20260919_users_email_reset" AS
WITH ranked AS (
    SELECT "id", "email",
           ROW_NUMBER() OVER (PARTITION BY LOWER("email") ORDER BY "id" ASC) AS rn
    FROM "users"
    WHERE "email" IS NOT NULL
)
SELECT "id", "email" FROM ranked WHERE rn > 1;

UPDATE "users" AS u
SET "email" = NULL
FROM "_migration_backup_20260919_users_email_reset" b
WHERE u."id" = b."id";

CREATE UNIQUE INDEX "users_email_lower_unique"
    ON "users" (LOWER("email"))
    WHERE "email" IS NOT NULL;

-- 审查项 P2-13：实例操作任务"查询 active task → 创建任务"存在检查-写入竞态。
-- 迁移前将同一实例多余的活跃任务标记为失败（保留最早一条），原状态先备份。
CREATE TABLE "_migration_backup_20260919_instance_tasks_status" AS
WITH ranked AS (
    SELECT "id", "status", "error", "finished_at",
           ROW_NUMBER() OVER (PARTITION BY "instance_id" ORDER BY "id" ASC) AS rn
    FROM "instance_tasks"
    WHERE "status" IN ('PENDING', 'PROCESSING')
)
SELECT "id", "status", "error", "finished_at" FROM ranked WHERE rn > 1;

UPDATE "instance_tasks" AS t
SET "status" = 'FAILED',
    "error" = 'Duplicate active task closed by migration',
    "finished_at" = NOW()
FROM "_migration_backup_20260919_instance_tasks_status" b
WHERE t."id" = b."id";

CREATE UNIQUE INDEX "instance_tasks_one_active_per_instance"
    ON "instance_tasks" ("instance_id")
    WHERE "status" IN ('PENDING', 'PROCESSING');

-- 备份上传任务同样处理（按用户维度，与 hasActiveUploadTask 的检查口径一致）。
CREATE TABLE "_migration_backup_20260919_backup_upload_tasks_status" AS
WITH ranked AS (
    SELECT "id", "status", "error", "finished_at",
           ROW_NUMBER() OVER (PARTITION BY "user_id" ORDER BY "id" ASC) AS rn
    FROM "backup_upload_tasks"
    WHERE "status" IN ('PENDING', 'PROCESSING')
)
SELECT "id", "status", "error", "finished_at" FROM ranked WHERE rn > 1;

UPDATE "backup_upload_tasks" AS t
SET "status" = 'FAILED',
    "error" = 'Duplicate active task closed by migration',
    "finished_at" = NOW()
FROM "_migration_backup_20260919_backup_upload_tasks_status" b
WHERE t."id" = b."id";

CREATE UNIQUE INDEX "backup_upload_tasks_one_active_per_user"
    ON "backup_upload_tasks" ("user_id")
    WHERE "status" IN ('PENDING', 'PROCESSING');
