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
/**
 * An endpoint record as `/api/endpoint/metadata` returns it.
 *
 * Everything about the host lives under `metadata`, and the agent's health
 * beside it as `host_status`. `EsEndpoint` below is the flat shape the
 * table wants; assigning one to the other left every cell undefined and the
 * page drew twenty-five rows of nothing.
 */
export interface EsEndpointMetadata {
  host_status?: string
  metadata?: {
    '@timestamp'?: string
    agent?: { id?: string; version?: string }
    host?: {
      hostname?: string
      name?: string
      ip?: string[]
      os?: { name?: string; full?: string; version?: string }
    }
    Endpoint?: {
      status?: string
      state?: { isolation?: boolean }
      policy?: { applied?: { name?: string; status?: string } }
    }
  }
}

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

/**
 * A signal document as `signals/search` returns it — ECS, not flat.
 *
 * `EsAlert` below is what the table wants; this is what the API gives, and
 * the two are not the same. Mapping between them by spreading `_source`
 * produced an alert whose every field was undefined, and a table of
 * twenty-five rows with nothing in them.
 */
export interface EsSignalSource {
  '@timestamp'?: string
  signal?: {
    status?: string
    rule?: { id?: string; rule_id?: string; name?: string; severity?: string; risk_score?: number }
  }
  host?: { name?: string; ip?: string; os?: { name?: string } }
  user?: { name?: string }
  process?: { name?: string }
  file?: { name?: string }
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
