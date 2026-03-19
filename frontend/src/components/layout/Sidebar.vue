<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRoute } from 'vue-router'
import type { Component } from 'vue'
import {
  LayoutDashboard, Monitor, ShieldAlert, Bell, Eye,
  FolderTree, Building2, Settings2, ListFilter, Lock,
  Flame, UsbIcon, Users, Activity, Shield,
  Webhook, ScrollText, Database, DatabaseBackup, Gauge, Radio, Play, Crosshair, Briefcase, Tag,
  AlertTriangle, Target, Bug, FileCheck, ShieldOff,
  Search, Zap, ChevronDown, Terminal, Hash,
  Mail, FileText, Key, Clock, Smartphone, Package, RefreshCw, Settings,
} from 'lucide-vue-next'

interface NavDivider { divider: true; label: string; collapsible?: boolean; key?: string; path?: undefined; icon?: undefined }
interface NavLink { divider?: false; label: string; path: string; icon: Component; group?: string }
type NavItem = NavDivider | NavLink

const route = useRoute()

/** Tracks which collapsible sections are open.  Vendor sections start collapsed. */
const openSections = ref<Set<string>>(new Set(['core', 'policy', 'security', 'management', 'devtools']))

function toggleSection(key: string): void {
  if (openSections.value.has(key)) {
    openSections.value.delete(key)
  } else {
    openSections.value.add(key)
  }
}

/** Auto-expand the section containing the active route. */
function isSectionOpen(key: string): boolean {
  if (openSections.value.has(key)) return true
  // Auto-expand if any child route is active
  return navItems.some(item => !item.divider && item.group === key && isActive(item.path))
}

const navItems: NavItem[] = [
  // ── SentinelOne (core) ────────────────────────────────────────────────────
  { divider: true, label: 'SENTINELONE', collapsible: true, key: 'core' },
  { label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard, group: 'core' },
  { label: 'Endpoints', path: '/endpoints', icon: Monitor, group: 'core' },
  { label: 'Threats', path: '/threats', icon: ShieldAlert, group: 'core' },
  { label: 'Alerts', path: '/alerts', icon: Bell, group: 'core' },
  { label: 'Deep Visibility', path: '/deep-visibility', icon: Eye, group: 'core' },

  { divider: true, label: 'POLICY', collapsible: true, key: 'policy' },
  { label: 'Accounts', path: '/accounts', icon: Briefcase, group: 'policy' },
  { label: 'Sites', path: '/sites', icon: Building2, group: 'policy' },
  { label: 'Groups', path: '/groups', icon: FolderTree, group: 'policy' },
  { label: 'Policies', path: '/policies', icon: Settings2, group: 'policy' },

  { divider: true, label: 'SECURITY CONFIG', collapsible: true, key: 'security' },
  { label: 'Exclusions', path: '/exclusions', icon: ListFilter, group: 'security' },
  { label: 'Blocklist', path: '/blocklist', icon: Lock, group: 'security' },
  { label: 'IOC', path: '/ioc', icon: Crosshair, group: 'security' },
  { label: 'Firewall Rules', path: '/firewall-rules', icon: Flame, group: 'security' },
  { label: 'Device Control', path: '/device-control', icon: UsbIcon, group: 'security' },

  { divider: true, label: 'MANAGEMENT', collapsible: true, key: 'management' },
  { label: 'Tags', path: '/tags', icon: Tag, group: 'management' },
  { label: 'Users', path: '/users', icon: Users, group: 'management' },
  { label: 'Activities', path: '/activities', icon: Activity, group: 'management' },

  { divider: true, label: 'DEV TOOLS', collapsible: true, key: 'devtools' },
  { label: 'Webhooks', path: '/webhooks', icon: Webhook, group: 'devtools' },
  { label: 'Request Audit', path: '/request-audit', icon: ScrollText, group: 'devtools' },
  { label: 'Export / Import', path: '/export-import', icon: DatabaseBackup, group: 'devtools' },
  { label: 'Rate Limit', path: '/rate-limit', icon: Gauge, group: 'devtools' },
  { label: 'Recording Proxy', path: '/recording-proxy', icon: Radio, group: 'devtools' },
  { label: 'Playbooks', path: '/playbooks', icon: Play, group: 'devtools' },

  // ── CrowdStrike ───────────────────────────────────────────────────────────
  { divider: true, label: 'CROWDSTRIKE', collapsible: true, key: 'cs' },
  { label: 'Dashboard', path: '/crowdstrike', icon: LayoutDashboard, group: 'cs' },
  { label: 'Hosts', path: '/crowdstrike/hosts', icon: Monitor, group: 'cs' },
  { label: 'Detections', path: '/crowdstrike/detections', icon: ShieldAlert, group: 'cs' },
  { label: 'Incidents', path: '/crowdstrike/incidents', icon: AlertTriangle, group: 'cs' },
  { label: 'Cases', path: '/crowdstrike/cases', icon: Briefcase, group: 'cs' },

  // ── Microsoft Defender ────────────────────────────────────────────────────
  { divider: true, label: 'MICROSOFT DEFENDER', collapsible: true, key: 'mde' },
  { label: 'Dashboard', path: '/defender', icon: LayoutDashboard, group: 'mde' },
  { label: 'Machines', path: '/defender/machines', icon: Monitor, group: 'mde' },
  { label: 'Alerts', path: '/defender/alerts', icon: ShieldAlert, group: 'mde' },
  { label: 'Indicators', path: '/defender/indicators', icon: Target, group: 'mde' },
  { label: 'TVM & Software', path: '/defender/vulnerabilities', icon: Bug, group: 'mde' },

  // ── Elastic Security ──────────────────────────────────────────────────────
  { divider: true, label: 'ELASTIC SECURITY', collapsible: true, key: 'es' },
  { label: 'Dashboard', path: '/elastic', icon: LayoutDashboard, group: 'es' },
  { label: 'Endpoints', path: '/elastic/endpoints', icon: Monitor, group: 'es' },
  { label: 'Rules', path: '/elastic/rules', icon: FileCheck, group: 'es' },
  { label: 'Alerts', path: '/elastic/alerts', icon: ShieldAlert, group: 'es' },
  { label: 'Cases', path: '/elastic/cases', icon: Briefcase, group: 'es' },
  { label: 'Exceptions', path: '/elastic/exceptions', icon: ShieldOff, group: 'es' },

  // ── Cortex XDR ────────────────────────────────────────────────────────────
  { divider: true, label: 'CORTEX XDR', collapsible: true, key: 'xdr' },
  { label: 'Dashboard', path: '/cortex-xdr', icon: LayoutDashboard, group: 'xdr' },
  { label: 'Incidents', path: '/cortex-xdr/incidents', icon: AlertTriangle, group: 'xdr' },
  { label: 'Alerts', path: '/cortex-xdr/alerts', icon: ShieldAlert, group: 'xdr' },
  { label: 'Endpoints', path: '/cortex-xdr/endpoints', icon: Monitor, group: 'xdr' },
  { label: 'Scripts', path: '/cortex-xdr/scripts', icon: Terminal, group: 'xdr' },
  { label: 'Hash Exceptions', path: '/cortex-xdr/hash-exceptions', icon: Hash, group: 'xdr' },

  // ── Splunk SIEM ───────────────────────────────────────────────────────────
  { divider: true, label: 'SPLUNK SIEM', collapsible: true, key: 'splunk' },
  { label: 'Dashboard', path: '/splunk', icon: LayoutDashboard, group: 'splunk' },
  { label: 'Search', path: '/splunk/search', icon: Search, group: 'splunk' },
  { label: 'Notables', path: '/splunk/notables', icon: ShieldAlert, group: 'splunk' },
  { label: 'Indexes', path: '/splunk/indexes', icon: Database, group: 'splunk' },
  { label: 'HEC', path: '/splunk/hec', icon: Zap, group: 'splunk' },

  // ── Microsoft Sentinel ────────────────────────────────────────────────────
  { divider: true, label: 'MICROSOFT SENTINEL', collapsible: true, key: 'sentinel' },
  { label: 'Dashboard', path: '/sentinel', icon: LayoutDashboard, group: 'sentinel' },
  { label: 'Incidents', path: '/sentinel/incidents', icon: AlertTriangle, group: 'sentinel' },
  { label: 'Watchlists', path: '/sentinel/watchlists', icon: Eye, group: 'sentinel' },
  { label: 'Threat Intel', path: '/sentinel/threat-intelligence', icon: Target, group: 'sentinel' },
  { label: 'Analytics', path: '/sentinel/analytics', icon: Activity, group: 'sentinel' },

  // ── Microsoft 365 / Graph ────────────────────────────────────────────
  { divider: true, label: 'MICROSOFT 365', collapsible: true, key: 'graph' },
  { label: 'Dashboard', path: '/graph', icon: LayoutDashboard, group: 'graph' },
  { label: 'Users', path: '/graph/users', icon: Users, group: 'graph' },
  { label: 'Groups', path: '/graph/groups', icon: FolderTree, group: 'graph' },
  { label: 'Conditional Access', path: '/graph/conditional-access', icon: Lock, group: 'graph' },
  { label: 'Devices', path: '/graph/devices', icon: Monitor, group: 'graph' },
  { label: 'Security Alerts', path: '/graph/security/alerts', icon: ShieldAlert, group: 'graph' },
  { label: 'Incidents', path: '/graph/security/incidents', icon: AlertTriangle, group: 'graph' },
  { label: 'Teams', path: '/graph/teams', icon: Building2, group: 'graph' },
  { label: 'Plan Comparison', path: '/graph/plans', icon: Briefcase, group: 'graph' },
  { label: 'Identity Protection', path: '/graph/identity-protection', icon: Shield, group: 'graph' },
  { label: 'Licenses', path: '/graph/licenses', icon: Key, group: 'graph' },
  { label: 'Sign-In Logs', path: '/graph/sign-in-logs', icon: Clock, group: 'graph' },
  { label: 'Audit Logs', path: '/graph/audit-logs', icon: ScrollText, group: 'graph' },
  { label: 'Compliance', path: '/graph/compliance', icon: FileCheck, group: 'graph' },
  { label: 'Configuration', path: '/graph/device-config', icon: Settings, group: 'graph' },
  { label: 'Autopilot', path: '/graph/autopilot', icon: Smartphone, group: 'graph' },
  { label: 'Apps', path: '/graph/apps', icon: Package, group: 'graph' },
  { label: 'Update Rings', path: '/graph/update-rings', icon: RefreshCw, group: 'graph' },
  { label: 'Mail', path: '/graph/mail', icon: Mail, group: 'graph' },
  { label: 'Files', path: '/graph/files', icon: FileText, group: 'graph' },
  { label: 'Attack Simulation', path: '/graph/security/attack-sim', icon: Target, group: 'graph' },
]

const isActive = (path: string): boolean => route.path === path || route.path.startsWith(path + '/')

/** Vendor brand colors for section badges. */
const vendorColors: Record<string, string> = {
  cs: 'text-red-400',
  mde: 'text-green-400',
  es: 'text-yellow-400',
  xdr: 'text-orange-400',
  splunk: 'text-emerald-400',
  sentinel: 'text-blue-400',
  graph: 'text-sky-400',
}

/** Group nav items by their section for rendering. */
const sections = computed(() => {
  const result: { divider: NavDivider; items: NavLink[] }[] = []
  let current: { divider: NavDivider; items: NavLink[] } | null = null

  for (const item of navItems) {
    if (item.divider) {
      current = { divider: item, items: [] }
      result.push(current)
    } else if (current) {
      current.items.push(item)
    }
  }
  return result
})
</script>

<template>
  <aside class="w-56 bg-s1-sidebar flex flex-col flex-shrink-0 border-r border-s1-border">
    <!-- Logo -->
    <div class="px-4 py-5 border-b border-s1-border">
      <div class="flex items-center gap-2">
        <div class="w-7 h-7 rounded bg-s1-primary flex items-center justify-center">
          <Shield class="w-4 h-4 text-white" />
        </div>
        <div>
          <div class="text-s1-text text-sm font-bold leading-tight">mockdr</div>
          <div class="text-s1-muted text-[10px]">7 platforms</div>
        </div>
      </div>
    </div>

    <!-- Nav -->
    <nav aria-label="Main navigation" class="flex-1 overflow-y-auto py-2 px-2">
      <template v-for="section in sections" :key="section.divider.label">
        <!-- Section header -->
        <button
          v-if="section.divider.collapsible"
          @click="toggleSection(section.divider.key!)"
          class="w-full flex items-center justify-between px-2 pt-4 pb-1 group cursor-pointer"
        >
          <span class="text-[10px] font-bold uppercase tracking-widest"
            :class="vendorColors[section.divider.key!] ?? 'text-s1-muted'">
            {{ section.divider.label }}
          </span>
          <ChevronDown
            class="w-3 h-3 text-s1-muted transition-transform duration-200"
            :class="{ '-rotate-90': !isSectionOpen(section.divider.key!) }"
          />
        </button>
        <div v-else class="px-2 pt-4 pb-1">
          <span class="text-[10px] font-bold text-s1-muted uppercase tracking-widest">
            {{ section.divider.label }}
          </span>
        </div>

        <!-- Section links (collapsible with smooth transition) -->
        <div
          v-show="isSectionOpen(section.divider.key ?? section.divider.label)"
          class="space-y-0.5"
        >
          <RouterLink
            v-for="item in section.items" :key="item.path"
            :to="item.path"
            class="flex items-center gap-3 px-3 py-1.5 rounded-lg text-[13px] transition-colors duration-150"
            :class="isActive(item.path)
              ? 'bg-s1-primary/15 text-s1-primary font-medium'
              : 'text-s1-subtle hover:text-s1-text hover:bg-s1-hover'"
          >
            <component :is="item.icon" class="w-3.5 h-3.5 flex-shrink-0" />
            {{ item.label }}
          </RouterLink>
        </div>
      </template>
    </nav>

    <!-- Footer -->
    <div class="p-3 border-t border-s1-border">
      <div class="text-[10px] text-s1-muted text-center">mockdr v2.1.0</div>
    </div>
  </aside>
</template>
