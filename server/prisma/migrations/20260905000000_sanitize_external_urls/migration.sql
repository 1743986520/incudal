-- Remove persisted values that could be interpreted as executable browser URLs.
-- Keep this migration idempotent so it is safe to apply during deployment.
UPDATE "hosts"
SET "probe_url" = NULL
WHERE "probe_url" IS NOT NULL
  AND (
    btrim("probe_url") = ''
    OR "probe_url" ~ '[[:cntrl:]]'
    OR btrim("probe_url") !~* '^https?://[^[:space:]/?#]+([/?#][^[:cntrl:][:space:]]*)?$'
  );

UPDATE "system_configs"
SET "value" = ''
WHERE "key" = 'footer_telegram_link'
  AND btrim("value") <> ''
  AND (
    "value" ~ '[[:cntrl:]]'
    OR btrim("value") !~* '^https://t[.]me/[^[:cntrl:][:space:]]+$'
  );
