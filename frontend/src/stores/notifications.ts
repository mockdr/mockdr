import { defineStore } from 'pinia'
import { ref } from 'vue'

export interface Notice {
  id: number
  kind: 'error' | 'info'
  text: string
}

let nextId = 1

/**
 * Transient notices surfaced to the user, announced to assistive technology
 * through the `aria-live` region in `Toasts.vue`.
 *
 * Every API client reports a failed request here, so a request that a view
 * swallows in a bare `catch {}` is still visible. Identical texts within a
 * few seconds collapse into one notice — a dashboard with six failing panels
 * says "backend unreachable" once.
 */
export const useNotificationsStore = defineStore('notifications', () => {
  const notices = ref<Notice[]>([])
  const recent = new Map<string, number>()

  function push(text: string, kind: Notice['kind'] = 'error', ttlMs = 6000): void {
    const now = Date.now()
    const last = recent.get(text)
    if (last !== undefined && now - last < 5000) return
    recent.set(text, now)
    const id = nextId++
    notices.value.push({ id, kind, text })
    setTimeout(() => dismiss(id), ttlMs)
  }

  function dismiss(id: number): void {
    notices.value = notices.value.filter((n) => n.id !== id)
  }

  function clear(): void {
    notices.value = []
    recent.clear()
  }

  return { notices, push, dismiss, clear }
})
