-- Remove soft-deleted instances' stale reservations so their addresses can be reused.
DELETE FROM "ip_addresses" AS ip
USING "instances" AS instance
WHERE ip."instance_id" = instance."id"
  AND instance."status" = 'deleted';

-- Backfill legacy primary-address columns before enforcing uniqueness. If the
-- database already contains a real collision, index creation deliberately
-- fails instead of silently choosing which live instance keeps the address.
INSERT INTO "ip_addresses" (
  "address", "type", "is_primary", "is_custom", "device",
  "host_id", "instance_id", "created_at"
)
SELECT instance."ipv4", 'inet4'::"IpType", TRUE, FALSE, 'eth0',
       instance."host_id", instance."id", NOW()
FROM "instances" AS instance
WHERE instance."ipv4" IS NOT NULL
  AND instance."status" <> 'deleted'
  AND NOT EXISTS (
    SELECT 1 FROM "ip_addresses" AS ip
    WHERE ip."instance_id" = instance."id"
      AND ip."type" = 'inet4'
      AND ip."address" = instance."ipv4"
  );

INSERT INTO "ip_addresses" (
  "address", "type", "is_primary", "is_custom", "device",
  "host_id", "instance_id", "created_at"
)
SELECT instance."ipv6", 'inet6'::"IpType", TRUE, FALSE, 'eth1',
       instance."host_id", instance."id", NOW()
FROM "instances" AS instance
WHERE instance."ipv6" IS NOT NULL
  AND instance."status" <> 'deleted'
  AND NOT EXISTS (
    SELECT 1 FROM "ip_addresses" AS ip
    WHERE ip."instance_id" = instance."id"
      AND ip."type" = 'inet6'
      AND ip."address" = instance."ipv6"
  );

DROP INDEX IF EXISTS "ip_addresses_host_id_address_idx";
CREATE UNIQUE INDEX "ip_addresses_host_id_address_key"
  ON "ip_addresses" ("host_id", "address");

-- Routed IPv6 addresses must be unique across hosts as well; overlapping or
-- later-reconfigured host subnets must never create a duplicate public IP.
CREATE UNIQUE INDEX "ip_addresses_global_ipv6_key"
  ON "ip_addresses" ("address")
  WHERE "type" = 'inet6';
