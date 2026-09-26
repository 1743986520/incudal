/** Match legacy coupon usages to paid billing records without a foreign key. */
export function matchCouponUsagesToBillingRecords(
  records: Array<{ type: string; amount: number; createdAt: Date }>,
  usages: Array<{ type: string; originalPrice: number; discountAmount: number; createdAt: Date }>
): Map<number, number> {
  const candidates: Array<{ recordIndex: number; usageIndex: number; distance: number }> = []

  for (const [recordIndex, record] of records.entries()) {
    const usageType = record.type === 'newPurchase' ? 'purchase' : record.type === 'renew' ? 'renewal' : null
    if (!usageType) continue
    for (const [usageIndex, usage] of usages.entries()) {
      if (usage.type !== usageType) continue
      const paidCents = Math.round((usage.originalPrice - usage.discountAmount) * 100)
      if (paidCents !== Math.round(record.amount * 100)) continue
      candidates.push({
        recordIndex,
        usageIndex,
        distance: Math.abs(record.createdAt.getTime() - usage.createdAt.getTime())
      })
    }
  }

  candidates.sort((a, b) => a.distance - b.distance || a.recordIndex - b.recordIndex || a.usageIndex - b.usageIndex)
  const matched = new Map<number, number>()
  const usedUsages = new Set<number>()
  for (const candidate of candidates) {
    if (matched.has(candidate.recordIndex) || usedUsages.has(candidate.usageIndex)) continue
    matched.set(candidate.recordIndex, candidate.usageIndex)
    usedUsages.add(candidate.usageIndex)
  }
  return matched
}
