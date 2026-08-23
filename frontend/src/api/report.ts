import axios from 'axios'

/**
 * Turn a failed request into one sentence for the notifications store.
 *
 * Returns `null` for a 401 (the clients handle that by re-authenticating)
 * so it is never announced twice.
 */
export function describeFailure(error: unknown, platform: string): string | null {
  if (!axios.isAxiosError(error)) return `${platform}: unexpected error`
  if (error.response) {
    const status = error.response.status
    if (status === 401) return null
    const path = error.config?.url ?? ''
    return `${platform}: ${status} on ${path}`
  }
  if (error.code === 'ECONNABORTED') return `${platform}: request timed out`
  return `${platform}: backend unreachable`
}

/** Report a failed request; safe to call from any client, before Pinia is ready. */
export async function reportFailure(error: unknown, platform: string): Promise<void> {
  const text = describeFailure(error, platform)
  if (!text) return
  try {
    const { useNotificationsStore } = await import('../stores/notifications')
    useNotificationsStore().push(text)
  } catch {
    /* no active Pinia (unit tests, module load) — nothing to announce to */
  }
}
