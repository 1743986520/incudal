<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import api, { type DeletionBillingReviewInput, type DeletionReservationReconciliation } from '@/api'
import { useToast } from '@/stores/toast'
import { translateError } from '@/utils/errorHandler'

const props = defineProps<{ snapshot: DeletionReservationReconciliation }>()
const { t } = useI18n()
const toast = useToast()
type Category = DeletionBillingReviewInput['category']
const categories = computed<Category[]>(() => {
  const instance = props.snapshot.instance
  const items: Category[] = []
  if (instance.billingMode === 'hourly') items.push('hourly')
  if (instance.trafficBillingMode === 'usage') items.push('usage')
  if (instance.deletionBillingMode === 'user_destroy') items.push('user_destroy')
  return items
})
const category = ref<Category | ''>('')
const evidenceReference = ref('')
const note = ref('')
const loading = ref(false)
const submitting = ref(false)
const reviews = ref<Array<{ id: number; actorId: number; createdAt: string; category: Category; evidenceReference: string; note: string }>>([])
let fingerprint = ''
let requestId = ''
const canSubmit = computed(() => category.value !== '' && props.snapshot.instance.deletionRequestedAt !== null
  && /^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$/.test(evidenceReference.value.trim())
  && note.value.trim().length >= 12 && note.value.trim().length <= 500 && !submitting.value)

async function load(): Promise<void> {
  loading.value = true
  try { reviews.value = (await api.admin.getDeletionBillingReviews(props.snapshot.instance.id)).reviews }
  catch (error) { toast.error(translateError(error)) }
  finally { loading.value = false }
}
watch(() => props.snapshot.instance.id, () => { category.value = ''; evidenceReference.value = ''; note.value = ''; fingerprint = ''; requestId = ''; void load() }, { immediate: true })

async function submit(): Promise<void> {
  const instance = props.snapshot.instance
  if (!canSubmit.value || !category.value || !instance.deletionRequestedAt) return
  const data = { category: category.value, evidenceReference: evidenceReference.value.trim(), note: note.value.trim(),
    expected: { instanceVersion: instance.version, hostId: instance.hostId, incusId: instance.incusId, requestedAt: instance.deletionRequestedAt } }
  const current = JSON.stringify(data)
  if (current !== fingerprint) { fingerprint = current; requestId = crypto.randomUUID() }
  submitting.value = true
  try {
    await api.admin.recordDeletionBillingReview(instance.id, { ...data, requestId })
    toast.success(t('deletionBillingReview.recorded'))
    note.value = ''; evidenceReference.value = ''; category.value = ''
    await load()
  } catch (error) { toast.error(translateError(error)) }
  finally { submitting.value = false }
}
</script>

<template>
  <section v-if="categories.length" class="border-t border-themed pt-3 space-y-3">
    <h3 class="font-semibold text-themed">{{ t('deletionBillingReview.title') }}</h3>
    <p class="text-sm text-themed-muted">{{ t('deletionBillingReview.intro') }}</p>
    <p v-if="!snapshot.instance.deletionRequestedAt" class="text-sm text-themed-muted">{{ t('deletionBillingReview.noTimestamp') }}</p>
    <form v-else class="space-y-3" @submit.prevent="submit">
      <label class="block text-sm text-themed">
        <span>{{ t('deletionBillingReview.category') }}</span>
        <select v-model="category" class="input mt-1 w-full">
          <option value="">{{ t('deletionBillingReview.select') }}</option>
          <option v-for="item in categories" :key="item" :value="item">{{ t(`deletionBillingReview.${item}`) }}</option>
        </select>
      </label>
      <label class="block text-sm text-themed"><span>{{ t('deletionReconciliation.evidence') }}</span><input v-model="evidenceReference" class="input mt-1 w-full" maxlength="128" autocomplete="off" /></label>
      <label class="block text-sm text-themed"><span>{{ t('deletionBillingReview.note') }}</span><textarea v-model="note" class="input mt-1 min-h-20 w-full resize-y" maxlength="500"></textarea></label>
      <button type="submit" class="btn-secondary btn-sm" :disabled="!canSubmit">{{ submitting ? t('common.submitting') : t('deletionBillingReview.submit') }}</button>
    </form>
    <p v-if="loading" class="text-sm text-themed-muted">{{ t('common.loading') }}</p>
    <ul v-else-if="reviews.length" class="space-y-2 text-sm text-themed-muted">
      <li v-for="review in reviews" :key="review.id" class="rounded border border-themed p-2 break-words">
        {{ t(`deletionBillingReview.${review.category}`) }} · #{{ review.actorId }} · {{ review.createdAt }} · {{ review.evidenceReference }}<br />{{ review.note }}
      </li>
    </ul>
  </section>
</template>
