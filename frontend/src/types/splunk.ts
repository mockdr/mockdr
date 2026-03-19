/** Splunk REST API response types. */

/** Splunk entry within an envelope. */
export interface SplunkEntry<T = Record<string, unknown>> {
  name: string
  id: string
  updated: string
  content: T
}

/** Splunk REST API JSON envelope. */
export interface SplunkEnvelope<T = Record<string, unknown>> {
  links: Record<string, unknown>
  origin: string
  updated: string
  generator: { build: string; version: string }
  entry: SplunkEntry<T>[]
  paging: { total: number; perPage: number; offset: number }
}

/** Splunk search results envelope. */
export interface SplunkSearchResults {
  results: Record<string, unknown>[]
  fields: { name: string }[]
  init_offset: number
  messages: { type: string; text: string }[]
}

/** Splunk auth login response. */
export interface SplunkAuthResponse {
  sessionKey: string
}

/** Splunk HEC response. */
export interface SplunkHecResponse {
  text: string
  code: number
}

/** Notable event fields. */
export interface SplunkNotable {
  event_id: string
  rule_name: string
  rule_title: string
  security_domain: string
  severity: string
  urgency: string
  status: string
  status_label: string
  owner: string
  src: string
  dest: string
  user: string
  description: string
  drilldown_search: string
  time: string
  _time: string
}

/** Splunk index info. */
export interface SplunkIndex {
  name: string
  totalEventCount: string
  currentDBSizeMB: string
  datatype: string
  disabled: boolean
}

/** Splunk search job status. */
export interface SplunkJobStatus {
  sid: string
  dispatchState: string
  doneProgress: number
  eventCount: number
  resultCount: number
  isDone: boolean
  isFailed: boolean
}

/** Splunk HEC token. */
export interface SplunkHecToken {
  name: string
  token: string
  index: string
  sourcetype: string
  disabled: boolean
}
