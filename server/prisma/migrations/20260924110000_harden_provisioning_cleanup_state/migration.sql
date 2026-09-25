-- Keep a failed provision in a non-retryable state while its Incus resource
-- is being verified and removed. Refunds and quota release happen only after
-- this flag is claimed and the Incus instance has been confirmed absent.
ALTER TABLE "instances"
  ADD COLUMN "provisioning_cleanup_pending" BOOLEAN NOT NULL DEFAULT false;
