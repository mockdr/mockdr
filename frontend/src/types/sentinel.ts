// ARM resource envelope
export interface ArmResource<T = Record<string, unknown>> {
  id: string
  name: string
  type: string
  etag?: string
  properties: T
}

export interface ArmList<T = Record<string, unknown>> {
  value: ArmResource<T>[]
  nextLink?: string
}

// Incident properties
export interface SentinelIncidentProps {
  title: string
  description: string
  severity: string
  status: string
  classification: string | null
  classificationReason: string | null
  owner: { assignedTo: string | null; email: string | null; ownerType: string }
  labels: { labelName: string; labelType: string }[]
  createdTimeUtc: string
  lastModifiedTimeUtc: string
  incidentNumber: number
  incidentUrl: string
  providerName: string
  providerIncidentId: string
  additionalData: {
    alertsCount: number
    bookmarksCount: number
    commentsCount: number
    alertProductNames: string[]
    tactics: string[]
    techniques: string[]
  }
}

// Alert properties
export interface SentinelAlertProps {
  alertDisplayName: string
  severity: string
  status: string
  productName: string
  vendorName: string
  tactics: string[]
  techniques: string[]
  timeGenerated: string
}

// Watchlist
export interface SentinelWatchlistProps {
  displayName: string
  description: string
  provider: string
  itemsSearchKey: string
  watchlistItemsCount: number
  created: string
  updated: string
}

// Threat indicator
export interface SentinelThreatIndicatorProps {
  displayName: string
  description: string
  pattern: string
  patternType: string
  source: string
  confidence: number
  threatTypes: string[]
  labels: string[]
  validFrom: string
  validUntil: string
  revoked: boolean
}

// Log Analytics response
export interface LogAnalyticsResponse {
  tables: { name: string; columns: { name: string; type: string }[]; rows: unknown[][] }[]
}

// Analytics rule
export interface SentinelAlertRuleProps {
  displayName: string
  description: string
  enabled: boolean
  severity: string
  tactics: string[]
  kind?: string
}
