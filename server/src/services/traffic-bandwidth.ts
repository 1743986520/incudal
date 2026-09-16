import { THROTTLE_BANDWIDTH } from '../lib/incus/incus-traffic.js'

const MB_IN_BYTES = 1024n * 1024n
const INCUS_BANDWIDTH_PATTERN = /^\d+(?:\.\d+)?(?:bit|kbit|mbit|gbit|tbit|B|kB|MB|GB|TB)$/i

export function isValidPlanTrafficLimitSpeed(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value === '0') return false
  if (/^\d+$/.test(value)) return BigInt(value) > 0n
  return INCUS_BANDWIDTH_PATTERN.test(value)
}

interface TrafficBandwidthSource {
  trafficBillingMode?: 'package' | 'usage'
  limitsIngress: string | null
  limitsEgress: string | null
  package?: {
    limitsIngress: string | null
    limitsEgress: string | null
  } | null
  packagePlan?: {
    trafficLimitSpeed: string | null
  } | null
}

export interface ResolvedTrafficBandwidthLimits {
  incusIngress: string | null
  incusEgress: string | null
  dbIngress: string | null
  dbEgress: string | null
}

export function normalizePlanTrafficLimitSpeed(trafficLimitSpeed: string | null | undefined): string | null {
  if (!trafficLimitSpeed || trafficLimitSpeed === '0') {
    return null
  }

  if (/^\d+$/.test(trafficLimitSpeed)) {
    const bytes = BigInt(trafficLimitSpeed)
    const mbps = Number(bytes / MB_IN_BYTES)
    return mbps > 0 ? `${mbps}Mbit` : null
  }

  return INCUS_BANDWIDTH_PATTERN.test(trafficLimitSpeed) ? trafficLimitSpeed : null
}

export function resolveTrafficBandwidthLimits(
  instance: TrafficBandwidthSource,
  options: { stripThrottleOverride?: boolean } = {}
): ResolvedTrafficBandwidthLimits {
  // Usage billing never applies a plan overage-speed cap. Ignore stale
  // instance-level limits left by a previous package-billed plan; only the
  // package's explicit base bandwidth policy remains applicable.
  if (instance.trafficBillingMode === 'usage') {
    return {
      incusIngress: instance.package?.limitsIngress ?? null,
      incusEgress: instance.package?.limitsEgress ?? null,
      dbIngress: null,
      dbEgress: null
    }
  }

  const planLimit = normalizePlanTrafficLimitSpeed(instance.packagePlan?.trafficLimitSpeed)
  if (planLimit) {
    return {
      incusIngress: planLimit,
      incusEgress: planLimit,
      dbIngress: planLimit,
      dbEgress: planLimit
    }
  }

  const stripThrottleOverride = options.stripThrottleOverride === true
  const configuredIngress = stripThrottleOverride && instance.limitsIngress === THROTTLE_BANDWIDTH
    ? null
    : instance.limitsIngress
  const configuredEgress = stripThrottleOverride && instance.limitsEgress === THROTTLE_BANDWIDTH
    ? null
    : instance.limitsEgress

  return {
    incusIngress: configuredIngress ?? instance.package?.limitsIngress ?? null,
    incusEgress: configuredEgress ?? instance.package?.limitsEgress ?? null,
    dbIngress: configuredIngress ?? null,
    dbEgress: configuredEgress ?? null
  }
}
