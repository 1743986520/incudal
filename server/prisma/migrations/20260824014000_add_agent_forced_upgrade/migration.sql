ALTER TABLE "host_agents"
  ADD COLUMN "upgrade_requested_at" TIMESTAMP(3),
  ADD COLUMN "upgrade_target_version" TEXT,
  ADD COLUMN "upgrade_force" BOOLEAN NOT NULL DEFAULT false;
