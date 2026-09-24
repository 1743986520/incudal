<script setup lang="ts">
import { formatDateYMD as formatDate } from '@/utils/formatters'
import { ref, computed, watch, defineAsyncComponent } from 'vue'
import { useI18n } from 'vue-i18n'
import { useThemeStore } from '@/stores/theme'
import { useConfigStore } from '@/stores/config'
import api from '@/api'
import type { InstanceBillingInfo, RenewPreview } from '@/types/api'
import { freeSiteCopy } from '@/utils/freeSiteFun'

const ApplyAffCodeModal = defineAsyncComponent(() => import('@/components/instance/modals/ApplyAffCodeModal.vue'))

const { t } = useI18n()
const themeStore = useThemeStore()
const configStore = useConfigStore()

interface Props {
  show: boolean
  instanceId: number
  instanceName: string
}

interface ApplyAffResult {
  success: boolean
  message: string
  replaced: boolean
  previousCode: string | null
  currentCode: string
  discountRate: number
  discountPercent: number
}

const props = defineProps<Props>()
const emit = defineEmits<{
  'update:show': [value: boolean]
  'success': []
}>()

// State
const loading = ref(false)
const renewing = ref(false)
const billingInfo = ref<InstanceBillingInfo | null>(null)
const userBalance = ref<number>(0)
const selectedMonths = ref<number>(1)
const error = ref<string>('')
const showAffModal = ref(false)
const affActionMessage = ref<string>('')

// 续费选项
const renewOptions = computed<RenewPreview[]>(() => {
  return billingInfo.value?.renewPreview || []
})

// 选中的续费方案
const selectedRenewOption = computed<RenewPreview | null>(() => {
  return renewOptions.value.find(r => r.months === selectedMonths.value) || null
})

// 是否有折扣（官方优惠券优先，其次 AFF 绑定）
const isOfficialCouponDiscount = computed(() => {
  const info = billingInfo.value?.officialCouponDiscount
  return !!info && info.discountPercent > 0
})

const hasDiscount = computed(() => {
  if (isOfficialCouponDiscount.value) return true
  return !!billingInfo.value?.affDiscount && billingInfo.value.affDiscount.discountPercent > 0
})

// 折扣百分比
const discountPercent = computed(() => {
  if (isOfficialCouponDiscount.value) {
    return billingInfo.value?.officialCouponDiscount?.discountPercent || 0
  }
  return billingInfo.value?.affDiscount?.discountPercent || 0
})

// 折扣标签（含优惠码）
const discountLabel = computed(() => {
  if (isOfficialCouponDiscount.value) {
    const code = billingInfo.value?.officialCouponDiscount?.couponCode
    return code ? `${t('billing.officialCouponDiscount')} (${code})` : t('billing.officialCouponDiscount')
  }
  const info = billingInfo.value?.affDiscount
  const base = t('billing.affDiscount')
  return info?.code ? `${base} (${info.code})` : base
})

// 优惠码按钮文案：已绑定 AFF → 更换；官方优惠券生效 → 替换官方优惠；无 → 添加
const affButtonLabel = computed(() => {
  if (billingInfo.value?.affDiscount) return t('billing.changeDiscountCode')
  if (isOfficialCouponDiscount.value) return t('billing.replaceOfficialCoupon')
  return t('billing.addDiscountCode')
})

// 弹窗内优惠码弹窗的当前来源与替换提示
const affCurrentSourceLabel = computed(() => {
  const info = billingInfo.value
  if (info?.affDiscount) return t('instance.subscription.applyAffSourceAff')
  if (info?.officialCouponDiscount) return t('instance.subscription.applyAffSourceOfficial')
  return null
})

const affReplaceHint = computed(() => {
  const info = billingInfo.value
  if (info?.affDiscount) return t('instance.subscription.applyAffReplaceHint')
  if (info?.officialCouponDiscount) return t('instance.subscription.applyAffReplaceOfficialHint')
  return null
})

// 优惠码弹窗提交成功后：重新请求计费信息与余额，刷新续费价格与余额不足状态
async function handleAffApplied(_result: ApplyAffResult): Promise<void> {
  showAffModal.value = false
  affActionMessage.value = t('billing.affCodeApplied')
  await loadBillingInfo()
}

// 实际支付价格（考虑折扣）
const actualPrice = computed(() => {
  if (!selectedRenewOption.value) return 0
  // Keep the calculation defensive for responses from older servers. The
  // billing endpoint now always returns discountedPrice, but using the
  // resolved discount here prevents the renewal dialog from charging/showing
  // the original amount when a stale response omits that field.
  const discountedPrice = selectedRenewOption.value.discountedPrice
  if (typeof discountedPrice === 'number' && Number.isFinite(discountedPrice)) {
    return discountedPrice
  }
  if (hasDiscount.value) {
    return Number((selectedRenewOption.value.price * (1 - discountPercent.value / 100)).toFixed(2))
  }
  return selectedRenewOption.value.price
})

// 是否余额不足
const insufficientBalance = computed(() => {
  if (!selectedRenewOption.value) return false
  return userBalance.value < actualPrice.value
})

// 续费后余额
const balanceAfterRenew = computed(() => {
  if (!selectedRenewOption.value) return userBalance.value
  return userBalance.value - actualPrice.value
})

// 是否为托管实例
const isHostedInstance = computed(() => {
  return billingInfo.value?.isHostedInstance ?? false
})

// 托管实例续费限制：是否满足续费条件（到期前7天内）
const canHostedInstanceRenew = computed(() => {
  if (!isHostedInstance.value) return true
  const restriction = billingInfo.value?.hostingRenewRestriction
  if (!restriction) return true
  const daysUntilExpire = billingInfo.value?.daysUntilExpire
  if (daysUntilExpire === null || daysUntilExpire === undefined) return true
  return daysUntilExpire <= restriction.daysBeforeExpire
})

// 托管实例距到期剩余天数
const daysUntilExpire = computed(() => {
  return billingInfo.value?.daysUntilExpire ?? null
})

// 格式化金额（API 返回的是元）
function formatMoney(amount: number): string {
  return amount.toFixed(2)
}

// 格式化日期

// 加载计费信息
async function loadBillingInfo() {
  loading.value = true
  error.value = ''
  
  try {
    const [billingRes, balanceRes] = await Promise.all([
      api.billing.getInstanceBilling(props.instanceId),
      api.billing.getUserBalance()
    ])
    
    billingInfo.value = billingRes.billing as InstanceBillingInfo
    userBalance.value = balanceRes.balance.balance
    
    // 默认选择1个月
    if (renewOptions.value.length > 0) {
      selectedMonths.value = renewOptions.value[0].months
    }
  } catch (err: any) {
    error.value = err.message || t('common.loadFailed')
  } finally {
    loading.value = false
  }
}

// 执行续费
async function handleRenew() {
  if (insufficientBalance.value || !selectedRenewOption.value || !canHostedInstanceRenew.value) return
  
  renewing.value = true
  error.value = ''
  
  try {
    await api.billing.renewInstance(props.instanceId, selectedMonths.value)
    emit('success')
    emit('update:show', false)
  } catch (err: any) {
    error.value = err.message || t('billing.renewFailed')
  } finally {
    renewing.value = false
  }
}

// 监听显示状态
watch(() => props.show, (newVal) => {
  if (newVal) {
    loadBillingInfo()
  } else {
    // 重置状态
    billingInfo.value = null
    userBalance.value = 0
    selectedMonths.value = 1
    error.value = ''
    showAffModal.value = false
    affActionMessage.value = ''
  }
})

function handleClose() {
  emit('update:show', false)
}
</script>

<template>
  <Teleport to="body">
    <Transition name="modal">
      <div
        v-if="show"
        class="fixed inset-0 z-50 flex items-center justify-center p-4"
        @click.self="handleClose"
      >
        <!-- Backdrop -->
        <div class="absolute inset-0 bg-black/50" @click="handleClose" />
        
        <!-- Modal -->
        <div
          class="relative w-full max-w-md rounded-lg shadow-xl"
          :class="themeStore.isDark ? 'bg-gray-900' : 'bg-white'"
        >
          <!-- Header -->
          <div
            class="flex items-center justify-between px-6 py-4 border-b"
            :class="themeStore.isDark ? 'border-gray-700' : 'border-gray-200'"
          >
            <h3 
              class="text-lg font-medium"
              :class="themeStore.isDark ? 'text-white' : 'text-gray-900'"
            >
              {{ t('billing.renewTitle') }}
            </h3>
            <button
              class="p-1 rounded hover:bg-gray-500/20"
              :class="themeStore.isDark ? 'text-gray-400' : 'text-gray-500'"
              @click="handleClose"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <!-- Content -->
          <div class="px-6 py-4">
            <!-- Loading -->
            <div v-if="loading" class="flex justify-center py-8">
              <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
            </div>

            <!-- Error -->
            <div v-else-if="error" class="py-4">
              <div class="p-3 rounded-lg bg-red-500/10 text-red-500 text-sm">
                {{ error }}
              </div>
            </div>

            <!-- Content -->
            <template v-else-if="billingInfo">
              <!-- 当前优惠信息与优惠码入口 -->
              <div
                v-if="hasDiscount || !isHostedInstance"
                class="mb-4 flex items-center justify-between gap-3 rounded-lg border px-3 py-2.5"
                :class="themeStore.isDark ? 'border-gray-700 bg-gray-800/50' : 'border-gray-200 bg-gray-50'"
              >
                <div class="min-w-0">
                  <div class="text-xs" :class="themeStore.isDark ? 'text-gray-500' : 'text-gray-500'">
                    {{ t('billing.currentDiscountSource') }}
                  </div>
                  <div class="mt-0.5 truncate text-sm font-medium" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">
                    <template v-if="hasDiscount">
                      {{ discountLabel }}<span class="ml-1 text-green-500">-{{ discountPercent }}%</span>
                    </template>
                    <template v-else>{{ t('billing.noDiscount') }}</template>
                  </div>
                </div>
                <button
                  v-if="!isHostedInstance"
                  type="button"
                  class="shrink-0 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors"
                  :class="themeStore.isDark
                    ? 'bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20'
                    : 'bg-emerald-50 text-emerald-700 hover:bg-emerald-100'"
                  @click="showAffModal = true"
                >
                  {{ affButtonLabel }}
                </button>
              </div>

              <!-- 优惠码更新成功提示 -->
              <div
                v-if="affActionMessage"
                class="mb-4 rounded-lg px-3 py-2 text-sm"
                :class="themeStore.isDark ? 'bg-emerald-500/10 text-emerald-300' : 'bg-emerald-50 text-emerald-700'"
              >
                {{ affActionMessage }}
              </div>

              <!-- 续费选项 -->
              <div class="mb-4">
                <label 
                  class="block text-sm font-medium mb-2"
                  :class="themeStore.isDark ? 'text-gray-300' : 'text-gray-700'"
                >
                  {{ t('billing.selectRenewPeriod') }}
                </label>
                <div class="grid grid-cols-3 gap-2">
                  <button
                    v-for="option in renewOptions"
                    :key="option.months"
                    class="py-2 px-3 rounded-lg border text-sm transition-colors"
                    :class="[
                      selectedMonths === option.months
                        ? 'border-blue-500 bg-blue-500/10 text-blue-500'
                        : themeStore.isDark
                          ? 'border-gray-700 text-gray-300 hover:border-gray-600'
                          : 'border-gray-200 text-gray-700 hover:border-gray-300'
                    ]"
                    @click="selectedMonths = option.months"
                  >
                    {{ t('billing.renewMonths', { months: option.months }) }}
                  </button>
                </div>
              </div>

              <!-- 费用详情 -->
              <div 
                v-if="selectedRenewOption"
                class="p-4 rounded-lg mb-4"
                :class="themeStore.isDark ? 'bg-gray-800' : 'bg-gray-50'"
              >
                <div class="space-y-2 text-sm">
                  <!-- 原价（有折扣时显示） -->
                  <div v-if="hasDiscount" class="flex justify-between">
                    <span :class="themeStore.isDark ? 'text-gray-400' : 'text-gray-600'">
                      {{ configStore.freeSiteMode ? freeSiteCopy.originalPrice : t('billing.originalPrice') }}
                    </span>
                    <span 
                      class="line-through"
                      :class="themeStore.isDark ? 'text-gray-500' : 'text-gray-400'"
                    >
                      ¥{{ formatMoney(selectedRenewOption.price) }}
                    </span>
                  </div>
                  <!-- 折扣信息 -->
                  <div v-if="hasDiscount" class="flex justify-between">
                    <span :class="themeStore.isDark ? 'text-gray-400' : 'text-gray-600'">
                      {{ discountLabel }}
                    </span>
                    <span class="text-green-500">
                      -{{ discountPercent }}%
                    </span>
                  </div>
                  <!-- 实付金额 -->
                  <div class="flex justify-between">
                    <span :class="themeStore.isDark ? 'text-gray-400' : 'text-gray-600'">
                      {{ configStore.freeSiteMode ? freeSiteCopy.finalPrice : (hasDiscount ? t('billing.actualPrice') : t('billing.renewPrice')) }}
                    </span>
                    <span 
                      class="font-medium"
                      :class="hasDiscount ? 'text-green-500' : (themeStore.isDark ? 'text-white' : 'text-gray-900')"
                    >
                      ¥{{ formatMoney(actualPrice) }}
                    </span>
                  </div>
                  <div class="flex justify-between">
                    <span :class="themeStore.isDark ? 'text-gray-400' : 'text-gray-600'">
                      {{ t('billing.newExpiresAt') }}
                    </span>
                    <span 
                      class="font-medium"
                      :class="themeStore.isDark ? 'text-white' : 'text-gray-900'"
                    >
                      {{ formatDate(selectedRenewOption.expiresAt) }}
                    </span>
                  </div>
                  <div class="border-t my-2" :class="themeStore.isDark ? 'border-gray-700' : 'border-gray-200'" />
                  <div class="flex justify-between">
                    <span :class="themeStore.isDark ? 'text-gray-400' : 'text-gray-600'">
                      {{ configStore.freeSiteMode ? freeSiteCopy.currentBalance : t('billing.currentBalance') }}
                    </span>
                    <span 
                      :class="insufficientBalance ? 'text-red-500' : themeStore.isDark ? 'text-white' : 'text-gray-900'"
                    >
                      ¥{{ formatMoney(userBalance) }}
                    </span>
                  </div>
                  <div v-if="!insufficientBalance" class="flex justify-between">
                    <span :class="themeStore.isDark ? 'text-gray-400' : 'text-gray-600'">
                      {{ configStore.freeSiteMode ? freeSiteCopy.balanceAfterRenew : t('billing.balanceAfterRenew') }}
                    </span>
                    <span :class="themeStore.isDark ? 'text-green-400' : 'text-green-600'">
                      ¥{{ formatMoney(balanceAfterRenew) }}
                    </span>
                  </div>
                </div>
              </div>

              <!-- 余额不足提示 -->
              <div 
                v-if="insufficientBalance"
                class="p-3 rounded-lg mb-4 text-sm"
                :class="themeStore.isDark ? 'bg-yellow-900/20 text-yellow-400' : 'bg-yellow-50 text-yellow-600'"
              >
                {{ t('billing.insufficientBalance') }}
                <a href="/wallet" class="underline ml-1">{{ t('billing.goRecharge') }}</a>
              </div>
              
              <!-- 托管实例续费限制提示 -->
              <div 
                v-if="isHostedInstance && !canHostedInstanceRenew && daysUntilExpire !== null"
                class="p-3 rounded-lg mb-4 text-sm"
                :class="themeStore.isDark ? 'bg-orange-900/20 text-orange-400' : 'bg-orange-50 text-orange-600'"
              >
                <div class="flex items-start gap-2">
                  <svg class="w-4 h-4 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                  <span>{{ t('billing.hostingRenewTooEarly', { days: daysUntilExpire }) }}</span>
                </div>
              </div>
            </template>
          </div>

          <!-- Footer -->
          <div
            class="flex justify-end gap-3 px-6 py-4 border-t"
            :class="themeStore.isDark ? 'border-gray-700' : 'border-gray-200'"
          >
            <button
              class="px-4 py-2 text-sm font-medium rounded-lg transition-colors"
              :class="themeStore.isDark
                ? 'text-gray-300 hover:bg-gray-800'
                : 'text-gray-700 hover:bg-gray-100'"
              @click="handleClose"
            >
              {{ t('common.cancel') }}
            </button>
            <button
              :disabled="loading || renewing || insufficientBalance || !selectedRenewOption || !canHostedInstanceRenew"
              class="px-4 py-2 text-sm font-medium rounded-lg transition-colors bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              @click="handleRenew"
            >
              {{ renewing ? t('billing.renewing') : t('billing.renew') }}
            </button>
          </div>
        </div>

        <!-- 绑定/更换优惠码弹窗 -->
        <ApplyAffCodeModal
          v-model:show="showAffModal"
          :instance-id="props.instanceId"
          :instance-name="props.instanceName"
          :renew-price="selectedRenewOption?.price ?? 0"
          :billing-cycle-label="''"
          :disabled="!configStore.affRebateEnabled"
          :disabled-reason="t('instance.subscription.applyAffDisabledByAdmin')"
          :current-code="billingInfo?.affDiscount?.code ?? null"
          :current-source-label="affCurrentSourceLabel"
          :replace-hint="affReplaceHint"
          @success="handleAffApplied"
        />
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.modal-enter-active,
.modal-leave-active {
  transition: opacity 0.2s ease;
}

.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}

.modal-enter-active .relative,
.modal-leave-active .relative {
  transition: transform 0.2s ease;
}

.modal-enter-from .relative,
.modal-leave-to .relative {
  transform: scale(0.95);
}
</style>
