/** The existing policy exempts an already-expired suspended fixed-plan
 * instance from the self-destroy traffic threshold. This narrow case has no
 * usage-based traffic debt and its immutable request-time refund quote is 0. */
export function canFinalizeExpiredUserDestroy(instance: {
  deletionBillingMode: string | null
  deletionBillingPending: boolean
  deletionOriginalStatus: string | null
  deletionRequestedAt: Date | null
  deletionRequestedById: number | null
  deletionRefundableValue: { isZero(): boolean } | null
  userId: number
  suspendReason: string | null
  expiresAt: Date | null
  packagePlanId: number | null
  billingMode: string
  trafficBillingMode: string
}): boolean {
  return instance.deletionBillingMode === 'user_destroy' && instance.deletionBillingPending
    && instance.deletionOriginalStatus === 'suspended' && instance.suspendReason === 'expired'
    && instance.deletionRequestedById === instance.userId && instance.packagePlanId !== null
    && instance.billingMode === 'package' && instance.trafficBillingMode === 'package'
    && instance.deletionRequestedAt !== null && instance.expiresAt !== null
    && instance.expiresAt.getTime() <= instance.deletionRequestedAt.getTime()
    && instance.deletionRefundableValue !== null && instance.deletionRefundableValue.isZero()
}
