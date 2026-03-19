import { defineStore } from 'pinia'
import { ref, watch } from 'vue'
import { useDebounce } from '@vueuse/core'
import type { ThreatRecord } from '../types'
import { threatsApi } from '../api/threats'

interface ThreatFilters {
  classifications: string
  mitigationStatuses: string
  analystVerdicts: string
  incidentStatuses: string
  siteIds: string
  query: string
}

const DEFAULT_FILTERS: ThreatFilters = {
  classifications: '',
  mitigationStatuses: '',
  analystVerdicts: '',
  incidentStatuses: '',
  siteIds: '',
  query: '',
}

/** Strips empty-string values from a filter object before sending to the API. */
function cleanFilters(f: ThreatFilters): Record<string, string> {
  return Object.fromEntries(
    Object.entries(f).filter(([, v]) => v !== ''),
  ) as Record<string, string>
}

/**
 * Pinia store for the threats list.
 *
 * Handles paginated fetching, debounced filtering, and bulk selection state.
 */
export const useThreatsStore = defineStore('threats', () => {
  const items = ref<ThreatRecord[]>([])
  const total = ref<number>(0)
  const nextCursor = ref<string | null>(null)
  const loading = ref<boolean>(false)
  const selected = ref<ThreatRecord[]>([])
  const filters = ref<ThreatFilters>({ ...DEFAULT_FILTERS })

  const debouncedFilters = useDebounce(filters, 300)

  /**
   * Fetch the threat list from the API.
   *
   * @param reset - When true (default) replaces the current list; when false appends.
   */
  async function fetchList(reset = true): Promise<void> {
    loading.value = true
    try {
      const params: Record<string, unknown> = { limit: 25, ...cleanFilters(filters.value) }
      if (!reset && nextCursor.value) params['cursor'] = nextCursor.value
      const res = await threatsApi.list(params)
      items.value = reset ? res.data : [...items.value, ...res.data]
      nextCursor.value = res.pagination?.nextCursor ?? null
      total.value = res.pagination?.totalItems ?? 0
    } finally {
      loading.value = false
    }
  }

  /**
   * Trigger a bulk threat action on selected threats (or a specific set).
   *
   * @param actionPath - Action name (e.g. mark-as-threat, resolve).
   * @param threatIds  - Optional explicit list of threat IDs; defaults to selected.
   */
  async function performAction(actionPath: string, threatIds: string[] | null = null): Promise<void> {
    const ids = threatIds ?? selected.value.map((t) => t.id)
    await threatsApi.action(actionPath, { filter: { ids } })
    await fetchList()
    selected.value = []
  }

  /** Toggle the selection state of a single threat. */
  function toggleSelect(threat: ThreatRecord): void {
    const idx = selected.value.findIndex((t) => t.id === threat.id)
    if (idx === -1) selected.value.push(threat)
    else selected.value.splice(idx, 1)
  }

  watch(debouncedFilters, () => fetchList(), { deep: true })

  return {
    items, total, nextCursor, loading, selected, filters,
    fetchList, performAction, toggleSelect,
  }
})
