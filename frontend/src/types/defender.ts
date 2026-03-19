/** Microsoft Defender for Endpoint OData response envelope. */
export interface MdeODataResponse<T> {
  '@odata.context': string
  value: T[]
}

/** MDE Machine (device/endpoint). */
export interface MdeMachine {
  machineId: string
  computerDnsName: string
  osPlatform: string
  osVersion: string
  healthStatus: string
  riskScore: string
  exposureLevel: string
  lastSeen: string
  lastIpAddress: string
  lastExternalIpAddress: string
  machineTags: string[]
  agentVersion: string
  isAadJoined: boolean
  aadDeviceId: string
  rbacGroupId: number
  rbacGroupName: string
  firstSeen: string
}

/** MDE Alert record. */
export interface MdeAlert {
  alertId: string
  title: string
  severity: string
  status: string
  category: string
  machineId: string
  computerDnsName: string
  description: string
  detectionSource: string
  threatFamilyName: string
  assignedTo: string
  creationTime: string
  lastUpdateTime: string
  resolvedTime: string
  classification: string
  determination: string
}

/** MDE Custom Indicator record. */
export interface MdeIndicator {
  indicatorId: string
  indicatorValue: string
  indicatorType: string
  action: string
  severity: string
  title: string
  description: string
  application: string
  generateAlert: boolean
  creationTimeDateTimeUtc: string
  createdBy: string
  expirationTime: string
}

/** MDE Software inventory record. */
export interface MdeSoftware {
  softwareId: string
  name: string
  vendor: string
  version: string
  weaknesses: number
  publicExploit: boolean
  activeAlert: boolean
  exposedMachines: number
  impactScore: number
}

/** MDE Vulnerability record. */
export interface MdeVulnerability {
  vulnerabilityId: string
  name: string
  description: string
  severity: string
  cvssV3: number
  exposedMachines: number
  publishedOn: string
  updatedOn: string
  publicExploit: boolean
}
