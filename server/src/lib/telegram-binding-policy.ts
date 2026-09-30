/**
 * Beta-only Telegram binding requirement. Disabled unless explicitly enabled
 * in the environment, keeping the production site behavior unchanged.
 */
export function isTelegramBindingRequired(): boolean {
  return /^(true|1)$/i.test(process.env.REQUIRE_TELEGRAM_BINDING?.trim() || '')
}
