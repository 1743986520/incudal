ALTER TABLE "hosts"
  ADD COLUMN "server_certificate" TEXT,
  ADD COLUMN "server_fingerprint" TEXT,
  ADD COLUMN "allow_private_network" BOOLEAN NOT NULL DEFAULT false;

-- Existing nodes remain present and can be migrated explicitly through the
-- administrator-only connection test. No global CA assumption is made here.
