// 实例列表共用的展示格式化逻辑。
// 从 InstancesView.vue 拆分而来,供列表表格、卡片与批次弹窗复用;
// 必须在组件 setup 上下文中调用(内部使用 useI18n / stores)。
import { useI18n } from 'vue-i18n'
import { useThemeStore } from '@/stores/theme'
import { useConfigStore } from '@/stores/config'
import { getLocalizedCountryName } from '@/utils/countryDisplay'
import { freeSiteCopy, getFreeSiteBillingCycleLabel } from '@/utils/freeSiteFun'
import type { Instance } from '@/types/api'
import type {
  InstanceExpiryInfo
} from '@/components/instance/instanceListShared'

export function useInstanceDisplay() {
  const { t, locale } = useI18n()
  const themeStore = useThemeStore()
  const configStore = useConfigStore()

  function getCountryLabel(code: string): string {
    return getLocalizedCountryName(code, locale.value, (key, fallback) => t(key, fallback))
  }

  function formatCurrency(value: number | null | undefined): string {
    if (configStore.freeSiteMode) return freeSiteCopy.moneyJustForShow
    return `¥${Number(value || 0).toFixed(2)}`
  }

  function getBatchRenewMonthsLabel(months: number): string {
    return configStore.freeSiteMode ? getFreeSiteBillingCycleLabel(months) : t('billing.renewMonths', { months })
  }

  // 遮蔽 IPv4 地址后两位，例如：1.2.3.4 -> 1.2.*.*
  function maskIpv4(ip: string | null | undefined): string | null {
    if (!ip) return null
    const parts = ip.split('.')
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.*.*`
    }
    return ip
  }

  function isIpv4Address(ip: string | null | undefined): boolean {
    if (!ip) return false
    return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)
  }

  function getHostIpv6(instance: Instance): string | null {
    let hostIpv6 = instance.hostNatPublicIpv6 || null
    if (!hostIpv6 && instance.hostIpAddress && instance.hostIpAddress.includes(':')) {
      hostIpv6 = instance.hostIpAddress
    }
    if (!hostIpv6 && instance.hostIpv6Gateway) {
      hostIpv6 = instance.hostIpv6Gateway
    }
    return hostIpv6
  }

  function getIps(instance: Instance): Array<{ip: string, type: 'ipv4' | 'ipv6'}> {
    const mode = instance.networkMode || instance.network_mode
    const ips: Array<{ip: string, type: 'ipv4' | 'ipv6'}> = []

    const natPublicIp = instance.natPublicIp || instance.host?.nat_public_ip
    const maskedNatIp = isIpv4Address(natPublicIp) ? maskIpv4(natPublicIp) : null
    const maskedPrivateIp = maskIpv4(instance.ipv4)
    const hostIpv6 = getHostIpv6(instance)

    if (mode === 'nat') {
      if (maskedNatIp) ips.push({ ip: maskedNatIp, type: 'ipv4' })
      else if (maskedPrivateIp) ips.push({ ip: maskedPrivateIp, type: 'ipv4' })
    } else if (mode === 'nat_ipv6') {
      if (maskedNatIp) ips.push({ ip: maskedNatIp, type: 'ipv4' })
      else if (maskedPrivateIp) ips.push({ ip: maskedPrivateIp, type: 'ipv4' })
      if (instance.ipv6) ips.push({ ip: instance.ipv6, type: 'ipv6' })
    } else if (mode === 'nat_ipv6_nat') {
      if (maskedNatIp) ips.push({ ip: maskedNatIp, type: 'ipv4' })
      else if (maskedPrivateIp) ips.push({ ip: maskedPrivateIp, type: 'ipv4' })
      if (hostIpv6) ips.push({ ip: hostIpv6, type: 'ipv6' })
    } else if (mode === 'ipv6_nat') {
      if (hostIpv6) ips.push({ ip: hostIpv6, type: 'ipv6' })
    } else if (mode === 'ipv6_only') {
      if (instance.ipv6) ips.push({ ip: instance.ipv6, type: 'ipv6' })
    } else {
      if (maskedPrivateIp) ips.push({ ip: maskedPrivateIp, type: 'ipv4' })
      if (instance.ipv6) ips.push({ ip: instance.ipv6, type: 'ipv6' })
    }

    return ips
  }

  function getInstanceNetworkMode(instance: Instance): string {
    return String((instance as any).networkMode || instance.network_mode || 'nat')
  }

  function getInstanceNetworkModeClass(instance: Instance): string {
    switch (getInstanceNetworkMode(instance)) {
      case 'nat':
        return themeStore.isDark ? 'bg-yellow-900/30 text-yellow-400' : 'bg-yellow-50 text-yellow-700'
      case 'nat_ipv6':
        return themeStore.isDark ? 'bg-blue-900/50 text-blue-400' : 'bg-blue-100 text-blue-600'
      case 'nat_ipv6_nat':
        return themeStore.isDark ? 'bg-cyan-900/50 text-cyan-400' : 'bg-cyan-100 text-cyan-600'
      case 'ipv6_only':
        return themeStore.isDark ? 'bg-purple-900/50 text-purple-400' : 'bg-purple-100 text-purple-600'
      case 'ipv6_nat':
        return themeStore.isDark ? 'bg-teal-900/50 text-teal-400' : 'bg-teal-100 text-teal-600'
      default:
        return themeStore.isDark ? 'bg-yellow-900/30 text-yellow-400' : 'bg-yellow-50 text-yellow-700'
    }
  }

  function getInstanceTypeBadgeClass(instance: Instance): string {
    return (instance as any).instanceType === 'vm'
      ? (themeStore.isDark ? 'bg-purple-900/50 text-purple-400' : 'bg-purple-100 text-purple-600')
      : (themeStore.isDark ? 'bg-green-900/50 text-green-400' : 'bg-green-100 text-green-600')
  }

  function getInstanceTypeDisplayLabel(instance: Instance): string {
    return (instance as any).instanceType === 'vm' ? t('common.instanceType.vm') : t('common.instanceType.container')
  }

  function getInstanceHostName(instance: Instance): string {
    return (instance as any).host?.name || (instance as any).host || '-'
  }

  function getInstancePackageName(instance: Instance): string | null {
    return (instance as any).packageName || (instance as any).package?.name || null
  }

  function isHourlyInstance(instance: Instance): boolean {
    const billingMode = (instance as any).billingMode || (instance as any).billing_mode
    return billingMode === 'hourly'
  }

  function getCardActionButtonClass(variant: 'default' | 'danger' = 'default'): string {
    if (variant === 'danger') {
      return themeStore.isDark
        ? 'border-red-500/20 bg-red-500/5 text-red-300 hover:border-red-500/35 hover:bg-red-500/10'
        : 'border-red-200 bg-red-50/70 text-red-600 hover:border-red-300 hover:bg-red-100'
    }

    return themeStore.isDark
      ? 'border-gray-800 bg-gray-900/60 text-gray-300 hover:border-gray-700 hover:bg-gray-900'
      : 'border-gray-200 bg-gray-50/80 text-gray-600 hover:border-gray-300 hover:bg-gray-100'
  }

  // 从镜像名称提取发行版标识（用于 DistroIcon 组件）
  function getDistroFromName(name: string): string {
    const lowerName = (name || '').toLowerCase()
    const distros = ['almalinux', 'alma', 'alpine', 'arch', 'centos', 'debian', 'fedora', 'gentoo', 'kali', 'mint', 'opensuse', 'suse', 'oracle', 'redhat', 'rhel', 'rockylinux', 'rocky', 'ubuntu', 'void']
    for (const distro of distros) {
      if (lowerName.includes(distro)) return distro
    }
    return 'linux'
  }

  // 获取付费实例的图标类型（根据节点名称判断）
  // 返回 'pro' | 'prime' | 'peer' | null
  function getPaidIconType(instance: Instance): 'pro' | 'prime' | 'peer' | null {
    // 只有付费实例才显示付费图标
    if (!instance.packagePlanId) return null

    // 如果节点名称以 PEER 开头（不区分大小写），则是托管实例，显示 peer 图标
    const hostName = instance.host?.name || ''
    if (/^PEER\d/i.test(hostName)) {
      return 'peer'
    }

    // 根据实例类型判断：虚拟机显示 prime，容器显示 pro
    return instance.instanceType === 'vm' ? 'prime' : 'pro'
  }

  // 格式化镜像名称：优先使用 imageName，否则去掉 images: 前缀
  function formatImageName(image: string, imageName?: string | null): string {
    if (imageName) return imageName
    return image?.replace(/^images:/, '') || ''
  }

  function formatExpiryDate(date: Date): string {
    const year = date.getFullYear()
    const month = String(date.getMonth() + 1).padStart(2, '0')
    const day = String(date.getDate()).padStart(2, '0')
    return `${year}-${month}-${day}`
  }

  function formatDate(value: string | null | undefined): string {
    if (!value) return '-'
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return value
    return formatExpiryDate(date)
  }

  // 将后端返回的中文批量操作原因映射为当前语言的提示文案
  function translateBatchReason(reason?: string): string {
    if (!reason) return t('instance.batch.unknownReason')
    if (reason === '实例不存在' || reason === '实例不存在或无权操作' || reason === '无权操作该实例') {
      return t('instance.batchReason.notFoundOrForbidden')
    }
    if (reason === '免费实例无需续费') {
      return t('instance.batchReason.freeNoRenew')
    }
    if (reason === '无法获取实例计费信息') {
      return t('instance.batchReason.billingUnavailable')
    }
    if (reason === '暂无可用续费选项') {
      return t('instance.batchReason.noRenewOptions')
    }
    if (reason === '该实例不支持当前续费时长') {
      return t('instance.batch.unsupportedPeriod')
    }
    if (reason === '免费实例不支持自动续费') {
      return t('instance.batchReason.freeNoAutoRenew')
    }
    if (reason === '已经开启自动续费') {
      return t('instance.batchReason.autoRenewAlreadyOn')
    }
    if (reason === '已经关闭自动续费') {
      return t('instance.batchReason.autoRenewAlreadyOff')
    }
    if (reason === '实例已删除') {
      return t('instance.batchReason.deleted')
    }
    if (reason === '实例正在创建中，无法销毁') {
      return t('instance.batchReason.creating')
    }
    if (reason === '实例已被封停，无法销毁，请先联系管理员解封') {
      return t('instance.batchReason.suspended')
    }
    const destroyTrafficLimitMatch = reason.match(/^当前月流量周期无法销毁，已用流量达到或超过\s+(.+)$/)
    if (destroyTrafficLimitMatch) {
      return t('instance.batchReason.destroyTrafficLimit', { limit: destroyTrafficLimitMatch[1] })
    }
    if (reason === '此套餐不支持用户自行删除及退款') {
      return t('instance.batchReason.destroyNotAllowed')
    }
    if (reason === '续费失败') {
      return t('instance.batchReason.renewFailed')
    }
    if (reason === '自动续费设置失败') {
      return t('instance.batchReason.autoRenewFailed')
    }
    if (reason === '销毁实例失败') {
      return t('instance.batchReason.destroyFailed')
    }

    const renewWindowMatch = reason.match(/^仅可在到期前\s*(\d+)\s*天内续费$/)
    if (renewWindowMatch) {
      return t('instance.batchReason.renewWindow', { days: renewWindowMatch[1] })
    }

    return reason
  }

  function getInstanceExpiryInfo(instance: Instance): InstanceExpiryInfo {
    if (isHourlyInstance(instance)) {
      return {
        dateText: null,
        remainingText: t('hourlyBilling.badge'),
        className: 'text-blue-500 dark:text-blue-400',
        title: null
      }
    }
    const expiresAt = instance.expires_at || (instance as any).expiresAt || null
    if (!expiresAt) {
      return {
        dateText: null,
        remainingText: t('instance.freeInstanceLabel'),
        className: 'text-green-500 dark:text-green-400',
        title: null
      }
    }

    const expires = new Date(expiresAt)
    if (Number.isNaN(expires.getTime())) {
      return {
        dateText: null,
        remainingText: t('instance.freeInstanceLabel'),
        className: 'text-green-500 dark:text-green-400',
        title: null
      }
    }

    const now = new Date()
    const diff = expires.getTime() - now.getTime()
    const remainingDays = Math.ceil(diff / (1000 * 60 * 60 * 24))
    const dateText = formatExpiryDate(expires)
    const autoRenew = (instance as any).autoRenew === true

    if (autoRenew) {
      return {
        dateText,
        remainingText: t('billing.autoRenewing'),
        className: 'text-green-500 dark:text-green-400',
        title: expires.toLocaleString()
      }
    }

    if (remainingDays <= 0) {
      return {
        dateText,
        remainingText: t('instance.expiredLabel'),
        className: 'text-red-500 dark:text-red-400',
        title: expires.toLocaleString()
      }
    }

    if (remainingDays <= 3) {
      return {
        dateText,
        remainingText: `${remainingDays} ${t('common.days')}`,
        className: 'text-red-500 dark:text-red-400',
        title: expires.toLocaleString()
      }
    }

    if (remainingDays <= 7) {
      return {
        dateText,
        remainingText: `${remainingDays} ${t('common.days')}`,
        className: 'text-yellow-500 dark:text-yellow-400',
        title: expires.toLocaleString()
      }
    }

    return {
      dateText,
      remainingText: `${remainingDays} ${t('common.days')}`,
      className: 'text-green-500 dark:text-green-400',
      title: expires.toLocaleString()
    }
  }

  return {
    getCountryLabel,
    formatCurrency,
    getBatchRenewMonthsLabel,
    maskIpv4,
    isIpv4Address,
    getHostIpv6,
    getIps,
    getInstanceNetworkMode,
    getInstanceNetworkModeClass,
    getInstanceTypeBadgeClass,
    getInstanceTypeDisplayLabel,
    getInstanceHostName,
    getInstancePackageName,
    isHourlyInstance,
    getCardActionButtonClass,
    getDistroFromName,
    getPaidIconType,
    formatImageName,
    formatExpiryDate,
    formatDate,
    translateBatchReason,
    getInstanceExpiryInfo
  }
}
