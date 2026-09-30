// 实例列表拆分组件共享的类型与常量。
// 仅承载类型定义,不包含任何运行时逻辑,避免让纯呈现组件各自重复声明。

export type InstanceLayoutMode = 'list' | 'card'

export type InstanceRowAction = 'start' | 'stop' | 'restart' | 'retry' | 'delete'

export type BatchSimpleAction = 'start' | 'stop' | 'restart' | 'sync'

export type InstanceOrderAction = 'top' | 'up' | 'down' | 'bottom'

export const INSTANCE_ORDER_ACTIONS: InstanceOrderAction[] = ['top', 'up', 'down', 'bottom']

export interface InstanceExpiryInfo {
  dateText: string | null
  remainingText: string
  className: string
  title: string | null
}

export interface BatchRenewOption {
  months: number
  price: number
  discountedPrice: number
  expiresAt: string
}

export interface BatchRenewPreviewItem {
  id: number
  name: string
  canRenew: boolean
  autoRenew: boolean
  reason?: string
  isHostedInstance: boolean
  daysUntilExpire: number | null
  options: BatchRenewOption[]
}

export interface BatchRenewEligibleItem extends BatchRenewPreviewItem {
  selectedOption: BatchRenewOption | null
}

export interface BatchDestroyRefundPreview {
  remainingDays: number
  remainingValue: number
  feeRate: number
  feeAmount: number
  refundAmount: number
  destroyCount: number
  maxRefundable: number
}

export interface BatchDestroyPreviewItem {
  id: number
  name: string
  canDestroy: boolean
  cannotDestroyReason: string
  isFreeInstance: boolean
  isFirstTime: boolean
  feeWaiverEligible: boolean
  refund: BatchDestroyRefundPreview
  instance: {
    id: number
    name: string
    hostName: string
    planName: string | null
  }
}
