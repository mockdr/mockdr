import { formatDistanceToNow, parseISO } from 'date-fns'

/**
 * Format an ISO timestamp as a human-readable relative time string.
 * @param ts - ISO 8601 timestamp string
 * @returns Relative time string (e.g., "2 hours ago")
 */
export function relativeTime(ts: string): string {
  if (!ts) return '—'
  try {
    return formatDistanceToNow(parseISO(ts), { addSuffix: true })
  } catch {
    return ts
  }
}

/**
 * Format an epoch timestamp (milliseconds) as a locale date string.
 * @param ms - Epoch timestamp in milliseconds
 * @returns Formatted date string
 */
export function formatEpoch(ms: number): string {
  if (!ms) return '—'
  return new Date(ms).toLocaleString()
}
