export const DATABASE_RESET_CONFIRMATION_TOKEN = 'I_UNDERSTAND_THIS_WILL_DELETE_ALL_DATA'

export function assertDatabaseResetAllowed(input: {
  shouldReset: boolean
  nodeEnv?: string
  confirmation?: string
}): void {
  if (!input.shouldReset || input.nodeEnv !== 'production') {
    return
  }

  if (input.confirmation !== DATABASE_RESET_CONFIRMATION_TOKEN) {
    throw new Error(
      `Production database reset requires RESET_DATABASE_CONFIRMATION=${DATABASE_RESET_CONFIRMATION_TOKEN}`
    )
  }
}
