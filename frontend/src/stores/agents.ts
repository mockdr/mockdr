import { defineStore } from 'pinia'
import { ref, watch } from 'vue'
import { useDebounce } from '@vueuse/core'
import type { Agent } from '../types'
import { agentsApi } from '../api/agents'

interface AgentFilters {
  osTypes: string
  networkStatuses: string
  siteIds: string
  groupIds: string
  query: string
}

const DEFAULT_FILTERS: AgentFilters = {
  osTypes: '',
  networkStatuses: '',
  siteIds: '',
  groupIds: '',
  query: '',
}

/** Strips empty-string values from a filter object before sending to the API. */
function cleanFilters(f: AgentFilters): Record<string, string> {
  return Object.fromEntries(
    Object.entries(f).filter(([, v]) => v !== ''),
  ) as Record<string, string>
}

/**
 * Pinia store for the agents (endpoints) list.
 *
 * Handles paginated fetching, debounced filtering, and bulk selection state.
 */
export const useAgentsStore = defineStore('agents', () => {
  const items = ref<Agent[]>([])
  const total = ref<number>(0)
  const nextCursor = ref<string | null>(null)
  const loading = ref<boolean>(false)
  const selected = ref<Agent[]>([])
  const filters = ref<AgentFilters>({ ...DEFAULT_FILTERS })

  const debouncedFilters = useDebounce(filters, 300)

  /**
   * Fetch the agent list from the API.
   *
   * @param reset - When true (default) replaces the current list; when false appends (load more).
   */
  async function fetchList(reset = true): Promise<void> {
    loading.value = true
    try {
      const params: Record<string, unknown> = { limit: 25, ...cleanFilters(filters.value) }
      if (!reset && nextCursor.value) params['cursor'] = nextCursor.value
      const res = await agentsApi.list(params)
      items.value = reset ? res.data : [...items.value, ...res.data]
      nextCursor.value = res.pagination?.nextCursor ?? null
      total.value = res.pagination?.totalItems ?? 0
    } finally {
      loading.value = false
    }
  }

  /**
   * Trigger a bulk agent action on selected agents (or a specific set).
   *
   * @param action   - Action name (e.g. connect, disconnect, initiate-scan).
   * @param agentIds - Optional explicit list of agent IDs; defaults to selected.
   */
  async function performAction(action: string, agentIds: string[] | null = null): Promise<void> {
    const ids = agentIds ?? selected.value.map((a) => a.id)
    await agentsApi.action(action, { filter: { ids } })
    await fetchList()
    selected.value = []
  }

  /** Toggle the selection state of a single agent. */
  function toggleSelect(agent: Agent): void {
    const idx = selected.value.findIndex((a) => a.id === agent.id)
    if (idx === -1) selected.value.push(agent)
    else selected.value.splice(idx, 1)
  }

  /** Returns true if the given agent is currently selected. */
  function isSelected(agent: Agent): boolean {
    return selected.value.some((a) => a.id === agent.id)
  }

  /** Clear all selected agents. */
  function clearSelection(): void {
    selected.value = []
  }

  watch(debouncedFilters, () => fetchList(), { deep: true })

  return {
    items, total, nextCursor, loading, selected, filters,
    fetchList, performAction, toggleSelect, isSelected, clearSelection,
  }
})
