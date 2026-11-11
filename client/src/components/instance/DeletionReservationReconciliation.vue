<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import api, { type DeletionReservationAttestation, type DeletionReservationReconciliation } from '@/api'
import { useToast } from '@/stores/toast'
import { translateError } from '@/utils/errorHandler'
import DeletionBillingReview from './DeletionBillingReview.vue'

const props = defineProps<{ instanceId: number }>()
const { t } = useI18n()
const toast = useToast()
const open = ref(false)
const loading = ref(false)
const submitting = ref(false)
const snapshot = ref<DeletionReservationReconciliation | null>(null)
const state = ref<'' | 'reserved' | 'released'>('')
const evidenceReference = ref('')
const reason = ref('')
const confirmed = ref(false)
let lastFingerprint = ''
let requestId = ''

const canSubmit = computed(() => snapshot.value?.instance.deletionRemoteDeleted === true && state.value !== '' && confirmed.value
  && /^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$/.test(evidenceReference.value.trim())
  && reason.value.trim().length >= 12 && reason.value.trim().length <= 500 && !submitting.value)
const hasCurrentEvidence = computed(() => snapshot.value?.reservation != null
  && ['reserved', 'released'].includes(snapshot.value.reservation.state)
  && snapshot.value.reservation.hostEpoch === snapshot.value.host.reservationEpoch)
const blockers = computed(() => {
  if (!snapshot.value) return []
  const { instance, host } = snapshot.value
  const result: string[] = []
  if (!instance.deletionRemoteDeleted && host.status !== 'online') result.push(t('deletionReconciliation.hostOffline'))
  if (instance.provisioningCleanupPending || !instance.deletionOriginalStatus || instance.deletionOriginalStatus === 'creating') result.push(t('deletionReconciliation.provisioning'))
  if (instance.deletionBillingMode === 'user_destroy') result.push(t('deletionReconciliation.userDestroy'))
  if (instance.billingMode === 'hourly') result.push(t('deletionReconciliation.hourly'))
  if (instance.trafficBillingMode === 'usage') result.push(t('deletionReconciliation.traffic'))
  return result
})

watch([state, evidenceReference, reason], () => { confirmed.value = false })

watch(() => props.instanceId, () => {
  snapshot.value = null
  open.value = false
  state.value = ''
  evidenceReference.value = ''
  reason.value = ''
  confirmed.value = false
  lastFingerprint = ''
  requestId = ''
})

async function loadSnapshot(): Promise<void> {
  open.value = true
  loading.value = true
  snapshot.value = null
  confirmed.value = false
  try {
    snapshot.value = await api.admin.getDeletionReservationReconciliation(props.instanceId)
  } catch (error) {
    toast.error(translateError(error))
  } finally {
    loading.value = false
  }
}

async function submit(): Promise<void> {
  if (!snapshot.value || !state.value || !canSubmit.value) return
  const { instance, host } = snapshot.value
  const payload = {
    state: state.value,
    evidenceReference: evidenceReference.value.trim(),
    reason: reason.value.trim(),
    expected: {
      instanceVersion: instance.version, hostId: instance.hostId, cpu: instance.cpu,
      memory: instance.memory, disk: instance.disk, portCount: instance.portCount, hostEpoch: host.reservationEpoch
    }
  }
  // Preserve the idempotency key for a retry of the identical attestation.
  const fingerprint = JSON.stringify(payload)
  if (fingerprint !== lastFingerprint) {
    requestId = crypto.randomUUID()
    lastFingerprint = fingerprint
  }
  submitting.value = true
  try {
    await api.admin.attestDeletionReservation(props.instanceId, { ...payload, requestId } satisfies DeletionReservationAttestation)
    toast.success(t('deletionReconciliation.recorded'))
    open.value = false
    snapshot.value = null
    confirmed.value = false
  } catch (error) {
    toast.error(translateError(error))
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <section class="rounded-lg border border-themed bg-themed p-4 space-y-3">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h2 class="font-semibold text-themed">{{ t('deletionReconciliation.title') }}</h2>
      <button type="button" class="btn-secondary btn-sm" :disabled="loading || submitting" @click="loadSnapshot">
        {{ loading ? t('common.loading') : t('deletionReconciliation.load') }}
      </button>
    </div>
    <p class="text-sm text-themed-muted">{{ t('deletionReconciliation.intro') }}</p>
    <ul v-if="open && blockers.length" class="list-disc space-y-1 pl-5 text-sm text-themed-muted">
      <li v-for="blocker in blockers" :key="blocker">{{ blocker }}</li>
    </ul>
    <p v-if="open && snapshot && !snapshot.instance.deletionRemoteDeleted" class="text-sm text-themed-muted">{{ t('deletionReconciliation.remotePending') }}</p>
    <p v-if="open && snapshot?.instance.deletionRemoteDeleted && hasCurrentEvidence" class="text-sm text-themed-muted">{{ t('deletionReconciliation.alreadyCurrent') }}</p>
    <form v-if="open && snapshot?.instance.deletionRemoteDeleted && !hasCurrentEvidence" class="space-y-3" @submit.prevent="submit">
      <p class="text-sm text-themed-muted">{{ t('deletionReconciliation.snapshot', {
        host: snapshot.instance.hostId, version: snapshot.instance.version, epoch: snapshot.host.reservationEpoch,
        cpu: snapshot.instance.cpu, memory: snapshot.instance.memory, disk: snapshot.instance.disk, ports: snapshot.instance.portCount
      }) }}</p>
      <p class="text-sm text-themed-muted">{{ t('deletionReconciliation.hostCounters', {
        cpu: snapshot.host.cpuUsed, memory: snapshot.host.memoryUsed, disk: snapshot.host.diskUsed, ports: snapshot.host.natPortsUsedCount
      }) }}</p>
      <fieldset class="space-y-1 text-sm text-themed">
        <legend class="font-medium">{{ t('deletionReconciliation.state') }}</legend>
        <label class="flex items-start gap-2"><input v-model="state" type="radio" value="reserved" /><span>{{ t('deletionReconciliation.reserved') }}</span></label>
        <label class="flex items-start gap-2"><input v-model="state" type="radio" value="released" /><span>{{ t('deletionReconciliation.released') }}</span></label>
      </fieldset>
      <label class="block text-sm text-themed">
        <span>{{ t('deletionReconciliation.evidence') }}</span>
        <input v-model="evidenceReference" class="input mt-1 w-full" maxlength="128" autocomplete="off" />
      </label>
      <label class="block text-sm text-themed">
        <span>{{ t('deletionReconciliation.reason') }}</span>
        <textarea v-model="reason" class="input mt-1 min-h-20 w-full resize-y" maxlength="500"></textarea>
      </label>
      <label class="flex items-start gap-2 text-sm text-themed">
        <input v-model="confirmed" type="checkbox" /><span>{{ t('deletionReconciliation.confirm') }}</span>
      </label>
      <button type="submit" class="btn-danger btn-sm" :disabled="!canSubmit">
        {{ submitting ? t('common.submitting') : t('deletionReconciliation.submit') }}
      </button>
    </form>
    <DeletionBillingReview v-if="open && snapshot" :key="snapshot.instance.id" :snapshot="snapshot" />
  </section>
</template>
