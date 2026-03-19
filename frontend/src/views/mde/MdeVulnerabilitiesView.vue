<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureMdeAuth, mdeVulnerabilitiesApi, mdeSoftwareApi } from '../../api/defender'
import type { MdeVulnerability, MdeSoftware } from '../../types/defender'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const activeTab = ref<'vulnerabilities' | 'software'>('vulnerabilities')
const vulnerabilities = ref<MdeVulnerability[]>([])
const software = ref<MdeSoftware[]>([])

function severityBadgeClass(severity: string): string {
  switch (severity) {
    case 'Critical': return 'bg-red-500/15 text-red-400'
    case 'High': return 'bg-orange-500/15 text-orange-400'
    case 'Medium': return 'bg-yellow-500/15 text-yellow-400'
    case 'Low': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

const EOL_NAMES = ['Adobe Flash Player', 'Microsoft Silverlight', 'Windows 7', 'Internet Explorer', 'Python 2.7', 'Apache Log4j', 'Java Runtime Environment']
const TORRENT_NAMES = ['qBittorrent', 'uTorrent', 'BitTorrent']
const DUAL_USE_NAMES = ['Mimikatz', 'Nmap', 'PsExec', 'Cobalt Strike', 'Wireshark']
const EDR_NAMES = ['SentinelOne', 'CrowdStrike', 'Defender for Endpoint', 'Cortex XDR', 'Elastic Endpoint']

function isEol(name: string): boolean { return EOL_NAMES.some(n => name?.includes(n)) }
function isTorrent(name: string): boolean { return TORRENT_NAMES.some(n => name?.includes(n)) }
function isDualUse(name: string): boolean { return DUAL_USE_NAMES.some(n => name?.includes(n)) }
function isEdr(name: string): boolean { return EDR_NAMES.some(n => name?.includes(n)) }
function isOutdated(name: string): boolean { return name?.includes('(outdated)') ?? false }

async function fetchData(): Promise<void> {
  loading.value = true
  try {
    await ensureMdeAuth()
    const [vulnRes, softRes] = await Promise.all([
      mdeVulnerabilitiesApi.list({ $top: 100 }),
      mdeSoftwareApi.list({ $top: 100 }),
    ])
    vulnerabilities.value = vulnRes.value ?? []
    software.value = softRes.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchData())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-green-500 font-bold">MDE</span> Vulnerabilities & Software
        </h1>
        <p class="text-s1-muted text-sm">Threat and vulnerability management</p>
      </div>
      <button @click="fetchData()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Tab toggle -->
    <div class="card overflow-hidden">
      <div class="flex border-b border-s1-border">
        <button
          @click="activeTab = 'vulnerabilities'"
          class="px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px"
          :class="activeTab === 'vulnerabilities'
            ? 'text-green-400 border-green-500'
            : 'text-s1-muted border-transparent hover:text-s1-text'"
        >
          Vulnerabilities ({{ vulnerabilities.length }})
        </button>
        <button
          @click="activeTab = 'software'"
          class="px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px"
          :class="activeTab === 'software'
            ? 'text-green-400 border-green-500'
            : 'text-s1-muted border-transparent hover:text-s1-text'"
        >
          Software ({{ software.length }})
        </button>
      </div>

      <!-- Vulnerabilities Table -->
      <div v-if="activeTab === 'vulnerabilities'">
        <table class="w-full">
          <thead class="border-b border-s1-border">
            <tr>
              <th class="table-header text-left">CVE ID</th>
              <th class="table-header text-left">Name</th>
              <th class="table-header text-left">Severity</th>
              <th class="table-header text-left">CVSS v3</th>
              <th class="table-header text-left">Exposed Machines</th>
              <th class="table-header text-left">Public Exploit</th>
            </tr>
          </thead>
          <tbody>
            <LoadingSkeleton v-if="loading && !vulnerabilities.length" :rows="8" />
            <template v-else>
              <tr v-for="vuln in vulnerabilities" :key="vuln.vulnerabilityId" class="table-row">
                <td class="table-cell">
                  <span class="font-mono text-xs text-s1-text">{{ vuln.vulnerabilityId }}</span>
                </td>
                <td class="table-cell text-sm text-s1-subtle truncate max-w-[250px]">{{ vuln.name }}</td>
                <td class="table-cell">
                  <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                    :class="severityBadgeClass(vuln.severity)">
                    {{ vuln.severity }}
                  </span>
                </td>
                <td class="table-cell">
                  <span class="font-mono text-sm text-s1-text">{{ vuln.cvssV3?.toFixed(1) ?? '--' }}</span>
                </td>
                <td class="table-cell text-sm text-s1-subtle">{{ vuln.exposedMachines }}</td>
                <td class="table-cell">
                  <span v-if="vuln.publicExploit" class="text-xs text-red-400 font-medium">Yes</span>
                  <span v-else class="text-xs text-s1-muted">No</span>
                </td>
              </tr>
            </template>
          </tbody>
        </table>

        <EmptyState
          v-if="!loading && !vulnerabilities.length"
          icon="--"
          title="No vulnerabilities"
          description="No vulnerabilities found in your environment."
        />
      </div>

      <!-- Software Table -->
      <div v-else>
        <!-- Compliance summary bar -->
        <div v-if="software.length" class="flex items-center gap-4 px-4 py-3 border-b border-s1-border bg-s1-card/50">
          <div class="flex items-center gap-1.5 text-xs">
            <span class="w-2 h-2 rounded-full bg-red-500"></span>
            <span class="text-red-400 font-medium">{{ software.filter(s => isEol(s.name)).length }} EOL</span>
          </div>
          <div class="flex items-center gap-1.5 text-xs">
            <span class="w-2 h-2 rounded-full bg-orange-500"></span>
            <span class="text-orange-400 font-medium">{{ software.filter(s => isTorrent(s.name)).length }} P2P/Torrent</span>
          </div>
          <div class="flex items-center gap-1.5 text-xs">
            <span class="w-2 h-2 rounded-full bg-purple-500"></span>
            <span class="text-purple-400 font-medium">{{ software.filter(s => isDualUse(s.name)).length }} Dual-Use</span>
          </div>
          <div class="flex items-center gap-1.5 text-xs">
            <span class="w-2 h-2 rounded-full bg-green-500"></span>
            <span class="text-green-400 font-medium">{{ software.filter(s => isEdr(s.name)).length }} EDR Agents</span>
          </div>
          <div class="flex items-center gap-1.5 text-xs ml-auto">
            <span class="text-s1-muted">Impact Score &gt; 7:</span>
            <span class="text-red-400 font-medium">{{ software.filter(s => s.impactScore > 7).length }}</span>
          </div>
        </div>

        <table class="w-full">
          <thead class="border-b border-s1-border">
            <tr>
              <th class="table-header text-left">Name</th>
              <th class="table-header text-left">Vendor</th>
              <th class="table-header text-left">Risk</th>
              <th class="table-header text-left">Weaknesses</th>
              <th class="table-header text-left">Exposed</th>
              <th class="table-header text-left">Impact</th>
              <th class="table-header text-left">Exploit</th>
              <th class="table-header text-left">Alert</th>
            </tr>
          </thead>
          <tbody>
            <LoadingSkeleton v-if="loading && !software.length" :rows="8" />
            <template v-else>
              <tr v-for="sw in software" :key="sw.softwareId" class="table-row">
                <td class="table-cell">
                  <div class="font-medium text-s1-text text-sm">{{ sw.name }}</div>
                  <div v-if="sw.version" class="text-[10px] text-s1-muted font-mono">v{{ sw.version }}</div>
                </td>
                <td class="table-cell text-sm text-s1-subtle">{{ sw.vendor }}</td>
                <td class="table-cell">
                  <span v-if="isEol(sw.name)" class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-500/15 text-red-400">
                    EOL
                  </span>
                  <span v-else-if="isTorrent(sw.name)" class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-orange-500/15 text-orange-400">
                    P2P
                  </span>
                  <span v-else-if="isDualUse(sw.name)" class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-500/15 text-purple-400">
                    DUAL-USE
                  </span>
                  <span v-else-if="isEdr(sw.name)" class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-green-500/15 text-green-400">
                    EDR
                  </span>
                  <span v-else-if="isOutdated(sw.name)" class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-yellow-500/15 text-yellow-400">
                    OUTDATED
                  </span>
                  <span v-else class="text-xs text-s1-muted">--</span>
                </td>
                <td class="table-cell text-sm text-s1-text">{{ sw.weaknesses }}</td>
                <td class="table-cell text-sm text-s1-subtle">{{ sw.exposedMachines }}</td>
                <td class="table-cell">
                  <span class="font-mono text-sm" :class="sw.impactScore > 7 ? 'text-red-400 font-bold' : sw.impactScore > 4 ? 'text-yellow-400' : 'text-s1-text'">
                    {{ sw.impactScore?.toFixed(1) ?? '--' }}
                  </span>
                </td>
                <td class="table-cell">
                  <span v-if="sw.publicExploit" class="text-xs text-red-400 font-medium">Yes</span>
                  <span v-else class="text-xs text-s1-muted">No</span>
                </td>
                <td class="table-cell">
                  <span v-if="sw.activeAlert" class="text-xs text-orange-400 font-medium">Yes</span>
                  <span v-else class="text-xs text-s1-muted">No</span>
                </td>
              </tr>
            </template>
          </tbody>
        </table>

        <EmptyState
          v-if="!loading && !software.length"
          icon="--"
          title="No software"
          description="No software inventory data available."
        />
      </div>
    </div>
  </div>
</template>
