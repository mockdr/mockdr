/** CrowdStrike API response envelope. */
export interface CsResponse<T> {
  meta: {
    query_time: number
    pagination?: { offset: number; limit: number; total: number }
    powered_by: string
    trace_id: string
  }
  resources: T[]
  errors: Array<{ code: number; message: string }>
}

/** CrowdStrike Host (device). */
export interface CsHost {
  device_id: string
  cid: string
  hostname: string
  local_ip: string
  external_ip: string
  mac_address: string
  os_version: string
  platform_name: string   // "Windows", "Mac", "Linux"
  platform_id: string
  status: string          // "normal", "contained", etc.
  first_seen: string
  last_seen: string
  agent_version: string
  site_name: string
  machine_domain: string
  product_type_desc: string   // "Workstation", "Server"
  chassis_type: string
  serial_number: string
  tags: string[]
  groups: string[]
  system_manufacturer: string
  system_product_name: string
  reduced_functionality_mode: string
  provision_status: string
  detection_suppression_status: string
  modified_timestamp: string
}

/** CrowdStrike Detection behaviour entry. */
export interface CsDetectionBehavior {
  behavior_id: string
  filename: string
  filepath: string
  scenario: string
  severity: number
  confidence: number
  timestamp: string
  cmdline: string
  tactic: string
  tactic_id: string
  technique: string
  technique_id: string
  user_name: string
  sha256: string
  md5: string
  ioc_type: string
  ioc_value: string
}

/** CrowdStrike Detection record. */
export interface CsDetection {
  composite_id: string
  device: {
    device_id: string
    hostname: string
    platform_name: string
    os_version: string
    external_ip: string
    status: string
    agent_version: string
  }
  behaviors: CsDetectionBehavior[]
  max_severity: number
  max_severity_displayname: string
  max_confidence: number
  status: string
  created_timestamp: string
  first_behavior: string
  last_behavior: string
  assigned_to_name: string
  date_updated: string
}

/** CrowdStrike Incident record. */
export interface CsIncident {
  incident_id: string
  cid: string
  host_ids: string[]
  hosts: Array<{ device_id: string; hostname: string; platform_name: string; os_version: string }>
  name: string
  description: string
  status: number   // 20=New, 25=Reopened, 30=InProgress, 40=Closed
  state: string
  tags: string[]
  fine_score: number
  start: string
  end: string
  created: string
  tactics: string[]
  techniques: string[]
  assigned_to_name: string
}

/** CrowdStrike Custom IOC record. */
export interface CsIoc {
  id: string
  type: string
  value: string
  action: string
  severity: string
  description: string
  platforms: string[]
  tags: string[]
  expiration: string
  applied_globally: boolean
  created_on: string
  modified_on: string
  created_by: string
}

/** CrowdStrike Case record. */
export interface CsCase {
  id: string
  title: string
  status: string
  type: string
  body: string
  tags: string[]
  detections: Array<{ id: string }>
  created_time: string
  last_modified_time: string
  created_by: string
}

/** CrowdStrike Host Group record. */
export interface CsHostGroup {
  id: string
  name: string
  description: string
  group_type: string
  assignment_rule: string
  created_timestamp: string
  modified_timestamp: string
}
