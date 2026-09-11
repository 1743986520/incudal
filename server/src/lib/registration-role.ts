export function resolveRegistrationRole(input: {
  email: string | null
  adminRegistrationEmails: string | null
  emailVerified: boolean
}): 'admin' | 'user' {
  if (!input.email || !input.emailVerified || !input.adminRegistrationEmails) {
    return 'user'
  }

  const normalizedEmail = input.email.trim().toLowerCase()
  const isConfiguredAdmin = parseAdminRegistrationEmailSuffixes(input.adminRegistrationEmails)
    .some(suffix => normalizedEmail.endsWith(suffix))

  return isConfiguredAdmin ? 'admin' : 'user'
}

/**
 * Normalize configured administrator email domains to suffixes such as
 * `@example.com`. Full email addresses are deliberately ignored so that an
 * old exact-address configuration cannot unexpectedly grant an entire domain
 * administrator access after upgrading.
 */
export function parseAdminRegistrationEmailSuffixes(value: string | null): string[] {
  if (!value) return []

  return [...new Set(value
    .split(/[\s,;]+/)
    .map(item => item.trim().toLowerCase())
    .filter(item => item.length > 1 && !item.slice(1).includes('@'))
    .map(item => item.startsWith('@') ? item : `@${item}`))]
}
