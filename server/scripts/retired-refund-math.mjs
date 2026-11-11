/** Exact-cent proration of paid service intervals at the deletion request time. */
export function retiredRefundCents(records, requestedAt, expiresAt) {
  const at = new Date(requestedAt).getTime()
  const expires = new Date(expiresAt).getTime()
  if (!Number.isSafeInteger(at) || !Number.isSafeInteger(expires) || !records.length) throw new Error('Invalid billing evidence')
  let numerator = 0n
  // Keep an exact rational until the final cent rounding.
  let denominator = 1n
  for (const record of records) {
    if (!/^[0-9]+(?:\.[0-9]{1,2})?$/.test(record.amount)) throw new Error('Invalid paid amount')
    const [whole, fraction = ''] = record.amount.split('.')
    const cents = BigInt(whole) * 100n + BigInt(fraction.padEnd(2, '0'))
    const start = new Date(record.period_start).getTime()
    const end = new Date(record.period_end).getTime()
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || end <= start) throw new Error('Invalid billing interval')
    const duration = BigInt(end - start)
    const remaining = BigInt(expires <= at ? 0 : Math.max(0, Math.min(end - at, end - start)))
    numerator = numerator * duration + cents * remaining * denominator
    denominator *= duration
  }
  return (numerator * 2n + denominator) / (2n * denominator)
}
