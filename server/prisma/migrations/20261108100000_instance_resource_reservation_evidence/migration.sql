-- Existing rows intentionally receive no reservation record: their provenance
-- cannot be inferred safely from instance status or aggregate host counters.
ALTER TABLE "hosts" ADD COLUMN "reservation_epoch" BIGINT NOT NULL DEFAULT 0;

CREATE TABLE "instance_resource_reservations" (
  "instance_id" INTEGER NOT NULL,
  "host_id" INTEGER NOT NULL,
  "state" TEXT NOT NULL CHECK ("state" IN ('reserved', 'released', 'unknown')),
  "generation" INTEGER NOT NULL DEFAULT 1 CHECK ("generation" > 0),
  "host_epoch" BIGINT NOT NULL,
  "cpu" INTEGER NOT NULL CHECK ("cpu" >= 0),
  "memory" INTEGER NOT NULL CHECK ("memory" >= 0),
  "disk" INTEGER NOT NULL CHECK ("disk" >= 0),
  "port_count" INTEGER NOT NULL CHECK ("port_count" >= 0),
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "instance_resource_reservations_pkey" PRIMARY KEY ("instance_id"),
  CONSTRAINT "instance_resource_reservations_instance_id_fkey" FOREIGN KEY ("instance_id") REFERENCES "instances"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "instance_resource_reservations_host_id_state_idx" ON "instance_resource_reservations"("host_id", "state");

CREATE FUNCTION "incudal_increment_reservation_epoch"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (OLD."cpu_used", OLD."memory_used", OLD."disk_used", OLD."nat_ports_used_count")
      IS DISTINCT FROM (NEW."cpu_used", NEW."memory_used", NEW."disk_used", NEW."nat_ports_used_count") THEN
    NEW."reservation_epoch" := OLD."reservation_epoch" + 1;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER "incudal_host_reservation_epoch"
BEFORE UPDATE OF "cpu_used", "memory_used", "disk_used", "nat_ports_used_count" ON "hosts"
FOR EACH ROW EXECUTE FUNCTION "incudal_increment_reservation_epoch"();

CREATE FUNCTION "incudal_invalidate_instance_reservation"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (OLD."host_id", OLD."cpu", OLD."memory", OLD."disk", OLD."port_limit", OLD."network_mode")
      IS DISTINCT FROM (NEW."host_id", NEW."cpu", NEW."memory", NEW."disk", NEW."port_limit", NEW."network_mode") THEN
    UPDATE "instance_resource_reservations" SET "state" = 'unknown', "updated_at" = CURRENT_TIMESTAMP
      WHERE "instance_id" = NEW."id" AND "state" <> 'unknown';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER "incudal_instance_reservation_invalidation"
AFTER UPDATE OF "host_id", "cpu", "memory", "disk", "port_limit", "network_mode" ON "instances"
FOR EACH ROW EXECUTE FUNCTION "incudal_invalidate_instance_reservation"();
