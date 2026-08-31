/** Elasticsearch search response envelope. */
export interface EsSearchResponse<T> {
  took: number
  hits: {
    total: { value: number; relation: string }
    hits: Array<{ _id: string; _index: string; _source: T }>
  }
}

/**
 * Kibana paginated list response — the detection-engine shape, `data` under
 * `perPage`.
 */
export interface KibanaListResponse<T> {
  page: number
  per_page: number
  total: number
  data: T[]
}

/**
 * The Cases API's list reply, which is not that shape: the records are under
 * `cases`, the page size comes back as `per_page` where the request takes
 * `perPage`, and three counts ride along. Declaring it as `KibanaListResponse`
 * had the view read `res.data`, which is `undefined` here — so the table was
 * empty over a store with cases in it, and neither the unit test (whose mock
 * copied the wrong shape) nor tsc could see it.
 */
export interface KibanaCasesResponse<T> {
  page: number
  per_page: number
  total: number
  cases: T[]
  count_open_cases: number
  count_in_progress_cases: number
  count_closed_cases: number
}

/** Elastic Security endpoint metadata. */
export interface EsEndpoint {
  agent_id: string
  hostname: string
  os: string
  agent_status: string
  isolation_status: string
  agent_version: string
  last_checkin: string
  policy_name: string
  ip_address: string
}

/** Elastic Security detection rule. */
export interface EsRule {
  id: string
  rule_id: string
  name: string
  description: string
  severity: string
  risk_score: number
  enabled: boolean
  type: string
  tags: string[]
  created_at: string
  updated_at: string
  created_by: string
  interval: string
}

/** Elastic Security alert (signal). */
export interface EsAlert {
  id: string
  rule_name: string
  severity: string
  risk_score: number
  status: string
  host_name: string
  timestamp: string
  rule_id: string
}

/** Elastic Security case. */
export interface EsCase {
  id: string
  title: string
  description: string
  status: string
  severity: string
  tags: string[]
  total_comment: number
  created_at: string
  updated_at: string
  created_by: { username: string }
  connector: { id: string; name: string }
}

/** Elastic Security case comment. */
export interface EsCaseComment {
  id: string
  comment: string
  created_at: string
  created_by: { username: string }
}

/** Elastic Security exception list. */
export interface EsExceptionList {
  id: string
  list_id: string
  name: string
  description: string
  type: string
  namespace_type: string
  total_items: number
  created_at: string
}

/** Elastic Security exception list item. */
export interface EsExceptionListItem {
  id: string
  item_id: string
  name: string
  description: string
  entries: Array<{ field: string; operator: string; type: string; value: string }>
  list_id: string
  created_at: string
}
