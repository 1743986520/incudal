/**
 * Validation helpers for URLs that may be rendered or opened by the browser.
 *
 * These helpers intentionally validate the parsed URL protocol instead of
 * relying on string prefixes. That prevents scheme variants such as
 * `javascript:` from reaching browser URL sinks.
 */

export interface UrlValidationSuccess {
  valid: true
  value: string | null
}

export interface UrlValidationFailure {
  valid: false
  message: string
}

export type UrlValidationResult = UrlValidationSuccess | UrlValidationFailure

const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001F\u007F]/

function invalid(message: string): UrlValidationFailure {
  return { valid: false, message }
}

function parseUrl(value: unknown, fieldName: string): URL | UrlValidationFailure {
  if (typeof value !== 'string') {
    return invalid(`${fieldName} must be a string`)
  }

  const trimmed = value.trim()
  if (!trimmed) {
    return invalid(`${fieldName} cannot be empty`)
  }

  if (CONTROL_CHARACTER_PATTERN.test(trimmed)) {
    return invalid(`${fieldName} contains invalid control characters`)
  }

  try {
    return new URL(trimmed)
  } catch {
    return invalid(`${fieldName} format is invalid`)
  }
}

/**
 * Validate an absolute HTTP(S) URL.
 */
export function validateHttpUrl(value: unknown, fieldName = 'URL'): UrlValidationResult {
  const parsed = parseUrl(value, fieldName)
  if (!(parsed instanceof URL)) {
    return parsed
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return invalid(`${fieldName} must use http:// or https://`)
  }

  return { valid: true, value: parsed.toString() }
}

/**
 * Validate an optional HTTP(S) URL. Empty strings and null are treated as
 * clearing the configured link.
 */
export function validateOptionalHttpUrl(value: unknown, fieldName = 'URL'): UrlValidationResult {
  if (value === null || value === undefined || (typeof value === 'string' && value.trim() === '')) {
    return { valid: true, value: null }
  }

  return validateHttpUrl(value, fieldName)
}

/**
 * Validate the public Telegram group link. The product configuration is
 * specifically for t.me links, so other HTTPS hosts are not accepted.
 */
export function validateOptionalTelegramUrl(value: unknown, fieldName = 'Telegram URL'): UrlValidationResult {
  const result = validateOptionalHttpUrl(value, fieldName)
  if (!result.valid || result.value === null) {
    return result
  }

  const parsed = new URL(result.value)
  if (parsed.protocol !== 'https:' || parsed.hostname.toLowerCase() !== 't.me' || parsed.pathname.length <= 1) {
    return invalid(`${fieldName} must use an https://t.me/<path> URL`)
  }

  return { valid: true, value: parsed.toString() }
}

/**
 * Return a safe HTTP(S) URL for response serialization. Invalid or empty
 * values are intentionally omitted from browser-facing API responses.
 */
export function getSafeHttpUrl(value: unknown): string | null {
  const result = validateOptionalHttpUrl(value)
  return result.valid ? result.value : null
}

/**
 * Return a safe Telegram URL for public configuration serialization.
 */
export function getSafeTelegramUrl(value: unknown): string | null {
  const result = validateOptionalTelegramUrl(value)
  return result.valid ? result.value : null
}
