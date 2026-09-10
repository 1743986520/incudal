export function resolveRegistrationRole(input: {
  email: string | null
  adminRegistrationEmails: string | null
  emailVerified: boolean
}): 'admin' | 'user' {
  if (!input.email || !input.emailVerified || !input.adminRegistrationEmails) {
    return 'user'
  }

  const normalizedEmail = input.email.trim().toLowerCase()
  const isConfiguredAdmin = input.adminRegistrationEmails
    .split(/[\s,;]+/)
    .map(item => item.trim().toLowerCase())
    .filter(Boolean)
    .includes(normalizedEmail)

  return isConfiguredAdmin ? 'admin' : 'user'
}
