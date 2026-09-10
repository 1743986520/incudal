ALTER TABLE "instance_tasks"
ADD COLUMN "execution_token" TEXT,
ADD COLUMN "lease_expires_at" TIMESTAMP(3);

CREATE UNIQUE INDEX "instance_tasks_execution_token_key"
ON "instance_tasks"("execution_token");

CREATE INDEX "instance_tasks_instance_id_status_lease_expires_at_idx"
ON "instance_tasks"("instance_id", "status", "lease_expires_at");
