/** Cortex XDR standard response envelope. */
export interface XdrResponse<T> {
  reply: T
}

/** Cortex XDR paginated list response. */
export interface XdrListResponse<T> {
  reply: {
    total_count: number
    result_count: number
    incidents?: T[]
    alerts?: T[]
    endpoints?: T[]
    scripts?: T[]
  }
}

/** Cortex XDR Incident. */
export interface XdrIncident {
  incident_id: string
  description: string
  alert_count: number
  severity: string
  status: string
  assigned_user_mail: string
  assigned_user_pretty_name: string
  creation_time: number
  modification_time: number
  hosts: string[]
  users: string[]
  incident_sources: string[]
  rule_based_score: number
  manual_severity: string
  starred: boolean
}

/** Cortex XDR Alert. */
export interface XdrAlert {
  alert_id: string
  severity: string
  category: string
  action: string
  description: string
  name: string
  source: string
  detection_timestamp: number
  endpoint_id: string
  host_name: string
  host_ip: string
  user_name: string
  mitre_technique_id_and_name: string
  mitre_tactic_id_and_name: string
  starred: boolean
  incident_id: string
}

/** Cortex XDR Endpoint. */
export interface XdrEndpoint {
  endpoint_id: string
  endpoint_name: string
  endpoint_type: string
  endpoint_status: string
  os_type: string
  ip: string[]
  domain: string
  alias: string
  first_seen: number
  last_seen: number
  content_version: string
  install_date: number
  endpoint_version: string
  is_isolated: string
  group_name: string
  operational_status: string
}

/** Cortex XDR Script. */
export interface XdrScript {
  script_id: string
  name: string
  description: string
  script_type: string
  modification_date: number
  created_by: string
  is_high_risk: boolean
}

/** Cortex XDR Hash Exception (blocklist/allowlist entry). */
export interface XdrHashException {
  exception_id: string
  hash: string
  list_type: string
  comment: string
  created_at: number
}

/** Cortex XDR incident extra data (detail endpoint). */
export interface XdrIncidentExtraData {
  incident: XdrIncident
  alerts: {
    total_count: number
    data: XdrAlert[]
  }
}
