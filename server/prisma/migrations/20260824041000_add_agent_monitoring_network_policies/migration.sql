CREATE TABLE "host_agent_audit_configs" (
  "id" SERIAL NOT NULL,
  "host_id" INTEGER NOT NULL,
  "enabled" BOOLEAN NOT NULL DEFAULT false,
  "interval_seconds" INTEGER NOT NULL DEFAULT 300,
  "batch_size" INTEGER NOT NULL DEFAULT 8,
  "last_requested_at" TIMESTAMP(3),
  "updated_by_id" INTEGER,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "host_agent_audit_configs_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "host_network_policies" (
  "id" SERIAL NOT NULL,
  "host_id" INTEGER NOT NULL,
  "created_by_id" INTEGER NOT NULL,
  "name" TEXT NOT NULL,
  "policy_type" TEXT NOT NULL,
  "target_mode" TEXT NOT NULL DEFAULT 'selected',
  "target_instance_ids" JSONB NOT NULL DEFAULT '[]',
  "config" JSONB NOT NULL DEFAULT '{}',
  "enabled" BOOLEAN NOT NULL DEFAULT false,
  "revision" INTEGER NOT NULL DEFAULT 1,
  "apply_status" TEXT NOT NULL DEFAULT 'pending',
  "apply_error" TEXT,
  "applied_at" TIMESTAMP(3),
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "host_network_policies_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "host_agent_audit_configs_host_id_key" ON "host_agent_audit_configs"("host_id");
CREATE INDEX "host_network_policies_host_id_enabled_idx" ON "host_network_policies"("host_id", "enabled");
CREATE INDEX "host_network_policies_host_id_updated_at_idx" ON "host_network_policies"("host_id", "updated_at" DESC);
ALTER TABLE "host_agent_audit_configs" ADD CONSTRAINT "host_agent_audit_configs_host_id_fkey" FOREIGN KEY ("host_id") REFERENCES "hosts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "host_network_policies" ADD CONSTRAINT "host_network_policies_host_id_fkey" FOREIGN KEY ("host_id") REFERENCES "hosts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
