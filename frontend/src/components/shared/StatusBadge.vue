<script setup lang="ts">
import { computed } from 'vue'

/** Colour-coded pill badge for agent, threat, incident, or analyst-verdict statuses. */
const props = defineProps<{ status: string; type?: string }>()

interface BadgeInfo { label: string; cls: string }
type StatusMap = Record<string, BadgeInfo>

const AGENT_STATUS: StatusMap = {
  connected:      { label: 'Online',       cls: 'bg-s1-success/15 text-s1-success' },
  disconnected:   { label: 'Disconnected', cls: 'bg-s1-danger/15 text-s1-danger' },
  not_applicable: { label: 'N/A',          cls: 'bg-s1-muted/15 text-s1-muted' },
}

const THREAT_STATUS: StatusMap = {
  mitigated:                { label: 'Mitigated',        cls: 'bg-s1-success/15 text-s1-success' },
  mitigated_with_suspicion: { label: 'Mitigated (Susp)', cls: 'bg-s1-warning/15 text-s1-warning' },
  active:                   { label: 'Active',           cls: 'bg-s1-danger/15 text-s1-danger' },
  blocked:                  { label: 'Blocked',          cls: 'bg-s1-primary/15 text-s1-primary' },
  suspicious:               { label: 'Suspicious',       cls: 'bg-s1-warning/15 text-s1-warning' },
  killed:                   { label: 'Killed',           cls: 'bg-s1-success/15 text-s1-success' },
  quarantined:              { label: 'Quarantined',      cls: 'bg-s1-cyan/15 text-s1-cyan' },
  remediated:               { label: 'Remediated',       cls: 'bg-s1-success/15 text-s1-success' },
}

// Threats use lowercase; alerts use UPPERCASE (real S1 API contract)
const INCIDENT_STATUS: StatusMap = {
  unresolved:  { label: 'Unresolved',  cls: 'bg-s1-danger/15 text-s1-danger' },
  in_progress: { label: 'In Progress', cls: 'bg-s1-warning/15 text-s1-warning' },
  resolved:    { label: 'Resolved',    cls: 'bg-s1-success/15 text-s1-success' },
  duplicate:   { label: 'Duplicate',   cls: 'bg-s1-muted/15 text-s1-muted' },
  UNRESOLVED:  { label: 'Unresolved',  cls: 'bg-s1-danger/15 text-s1-danger' },
  IN_PROGRESS: { label: 'In Progress', cls: 'bg-s1-warning/15 text-s1-warning' },
  RESOLVED:    { label: 'Resolved',    cls: 'bg-s1-success/15 text-s1-success' },
  DUPLICATE:   { label: 'Duplicate',   cls: 'bg-s1-muted/15 text-s1-muted' },
}

const VERDICT: StatusMap = {
  true_positive:  { label: 'True Positive',  cls: 'bg-s1-danger/15 text-s1-danger' },
  false_positive: { label: 'False Positive', cls: 'bg-s1-success/15 text-s1-success' },
  suspicious:     { label: 'Suspicious',     cls: 'bg-s1-warning/15 text-s1-warning' },
  undefined:      { label: 'Undefined',      cls: 'bg-s1-muted/15 text-s1-muted' },
  TRUE_POSITIVE:  { label: 'True Positive',  cls: 'bg-s1-danger/15 text-s1-danger' },
  FALSE_POSITIVE: { label: 'False Positive', cls: 'bg-s1-success/15 text-s1-success' },
  SUSPICIOUS:     { label: 'Suspicious',     cls: 'bg-s1-warning/15 text-s1-warning' },
  UNDEFINED:      { label: 'Undefined',      cls: 'bg-s1-muted/15 text-s1-muted' },
}

const MAP: Record<string, StatusMap> = {
  agent: AGENT_STATUS,
  threat: THREAT_STATUS,
  incident: INCIDENT_STATUS,
  verdict: VERDICT,
}

const info = computed<BadgeInfo>(() => {
  const map = MAP[props.type ?? 'agent'] ?? AGENT_STATUS
  return map[props.status] ?? { label: props.status, cls: 'bg-s1-muted/15 text-s1-muted' }
})
</script>

<template>
  <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium" :class="info.cls">
    {{ info.label }}
  </span>
</template>
