<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { Radio, RefreshCw, Save, Trash2, ChevronDown, ChevronUp } from 'lucide-vue-next'
import { proxyApi } from '../api/system'
import type { ProxyConfig, ProxyRecording, VendorInfo, VendorAuth } from '../types'

const config = ref<ProxyConfig | null>(null)
const recordings = ref<ProxyRecording[]>([])
const vendorList = ref<VendorInfo[]>([])
const loading = ref(true)
const saving = ref(false)
const clearing = ref(false)

const draftMode = ref<'off' | 'record' | 'replay'>('off')

// Per-vendor draft configs keyed by vendor name.
interface VendorDraft {
  base_url: string
  auth: VendorAuth
  enabled: boolean
  expanded: boolean
}
const vendorDrafts = ref<Record<string, VendorDraft>>({})

// Which vendor tab is selected for the recordings filter.
const recordingFilter = ref<string>('all')

function emptyAuth(type: string): VendorAuth {
  if (type === 'oauth2') return { type: 'oauth2', client_id: '', client_secret: '', token_url: '' }
  if (type === 'basic') return { type: 'basic', username: '', password: '', api_key: '' }
  if (type === 'hmac') return { type: 'hmac', key_id: '', key_secret: '' }
  return { type: 'api_token', token: '' }
}

async function fetchAll(): Promise<void> {
  loading.value = true
  try {
    const [cfgRes, recRes, vendRes] = await Promise.all([
      proxyApi.getConfig(),
      proxyApi.listRecordings(),
      proxyApi.listVendors(),
    ])
    config.value = cfgRes.data
    draftMode.value = cfgRes.data.mode
    recordings.value = recRes.data
    vendorList.value = vendRes.data

    // Initialize vendor drafts from server config.
    const drafts: Record<string, VendorDraft> = {}
    for (const v of vendRes.data) {
      const existing = cfgRes.data.vendors?.[v.vendor]
      drafts[v.vendor] = {
        base_url: existing?.base_url ?? '',
        auth: existing?.auth
          ? { ...existing.auth }
          : emptyAuth(v.default_auth_type),
        enabled: existing?.enabled ?? false,
        expanded: !!existing?.base_url,
      }
    }
    vendorDrafts.value = drafts
  } finally {
    loading.value = false
  }
}

async function saveConfig(): Promise<void> {
  saving.value = true
  try {
    // Build per-vendor payload.
    const vendors = Object.entries(vendorDrafts.value)
      .filter(([, d]) => d.enabled && d.base_url)
      .map(([vendor, d]) => ({
        vendor,
        base_url: d.base_url,
        auth: d.auth,
        enabled: d.enabled,
      }))

    const res = await proxyApi.setConfig({ mode: draftMode.value, vendors })
    config.value = res.data
    draftMode.value = res.data.mode
  } finally {
    saving.value = false
  }
}

async function clearRecordings(): Promise<void> {
  clearing.value = true
  try {
    await proxyApi.clearRecordings()
    recordings.value = []
    if (config.value) config.value = { ...config.value, recording_count: 0 }
  } finally {
    clearing.value = false
  }
}

function toggleVendor(vendor: string): void {
  const d = vendorDrafts.value[vendor]
  if (d) {
    d.expanded = !d.expanded
  }
}

const filteredRecordings = computed(() => {
  if (recordingFilter.value === 'all') return recordings.value
  return recordings.value.filter(r => r.vendor === recordingFilter.value)
})

const configuredVendorCount = computed(() =>
  Object.values(vendorDrafts.value).filter(d => d.enabled && d.base_url).length
)

const showConnectionSettings = computed(() => draftMode.value !== 'off')

function methodClass(method: string): string {
  const map: Record<string, string> = {
    GET: 'bg-s1-primary/15 text-s1-primary',
    POST: 'bg-green-500/15 text-green-400',
    PUT: 'bg-s1-warning/15 text-s1-warning',
    PATCH: 'bg-purple-500/15 text-purple-400',
    DELETE: 'bg-red-500/15 text-red-400',
  }
  return map[method] ?? 'bg-s1-hover text-s1-subtle'
}

function statusClass(status: number): string {
  if (status < 300) return 'bg-green-500/15 text-green-400'
  if (status < 400) return 'bg-s1-warning/15 text-s1-warning'
  if (status < 500) return 'bg-red-500/15 text-red-400'
  return 'bg-red-700/20 text-red-300'
}

function vendorBadgeClass(vendor: string): string {
  const map: Record<string, string> = {
    s1: 'bg-purple-500/15 text-purple-400',
    crowdstrike: 'bg-red-500/15 text-red-400',
    mde: 'bg-blue-500/15 text-blue-400',
    elastic: 'bg-yellow-500/15 text-yellow-400',
    cortex_xdr: 'bg-orange-500/15 text-orange-400',
    splunk: 'bg-green-500/15 text-green-400',
    sentinel: 'bg-cyan-500/15 text-cyan-400',
    graph: 'bg-indigo-500/15 text-indigo-400',
  }
  return map[vendor] ?? 'bg-s1-hover text-s1-subtle'
}

function authLabel(type: string): string {
  const map: Record<string, string> = {
    api_token: 'API Token',
    oauth2: 'OAuth2 Client Credentials',
    basic: 'Basic Auth / API Key',
    hmac: 'HMAC',
  }
  return map[type] ?? type
}

onMounted(() => fetchAll())
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Recording Proxy</h1>
        <p class="text-s1-muted text-sm">Record real vendor API exchanges or replay saved responses</p>
      </div>
      <button @click="fetchAll" :disabled="loading" class="btn-ghost flex items-center gap-1.5 text-sm">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Loading skeleton -->
    <div v-if="loading" class="card p-6 animate-pulse space-y-3">
      <div class="h-4 bg-s1-hover rounded w-1/4" />
      <div class="h-4 bg-s1-hover rounded w-1/2" />
      <div class="h-4 bg-s1-hover rounded w-1/3" />
    </div>

    <template v-else>
      <div class="grid md:grid-cols-2 gap-6">
        <!-- Mode panel -->
        <div class="card p-6 space-y-5">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-lg bg-s1-primary/15 flex items-center justify-center">
              <Radio class="w-5 h-5 text-s1-primary" />
            </div>
            <div>
              <h2 class="text-s1-text font-semibold">Proxy Mode</h2>
              <p class="text-s1-muted text-xs">Control how API requests are handled</p>
            </div>
          </div>

          <!-- Mode toggle buttons -->
          <div class="flex rounded-lg border border-s1-border overflow-hidden">
            <button
              v-for="m in (['off', 'record', 'replay'] as const)"
              :key="m"
              @click="draftMode = m"
              class="flex-1 py-2 text-sm font-medium transition-colors capitalize"
              :class="draftMode === m
                ? 'bg-s1-primary text-white'
                : 'text-s1-subtle hover:text-s1-text hover:bg-s1-hover'"
            >
              {{ m }}
            </button>
          </div>

          <button
            @click="saveConfig"
            :disabled="saving"
            class="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium text-white bg-s1-primary hover:bg-s1-primary-dark transition-colors disabled:opacity-50"
          >
            <Save class="w-4 h-4" />
            {{ saving ? 'Saving...' : 'Apply Configuration' }}
          </button>
        </div>

        <!-- Live stats panel -->
        <div class="card p-6 space-y-4">
          <h2 class="text-s1-text font-semibold">Live Status</h2>

          <div class="grid grid-cols-3 gap-3">
            <div class="bg-s1-bg rounded-lg p-3 text-center">
              <div
                class="text-2xl font-bold uppercase"
                :class="{
                  'text-s1-muted': config?.mode === 'off',
                  'text-red-400': config?.mode === 'record',
                  'text-s1-primary': config?.mode === 'replay',
                }"
              >
                {{ config?.mode ?? '\u2014' }}
              </div>
              <div class="text-s1-muted text-xs mt-0.5">Mode</div>
            </div>
            <div class="bg-s1-bg rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-s1-cyan font-mono">{{ config?.recording_count ?? 0 }}</div>
              <div class="text-s1-muted text-xs mt-0.5">Recordings</div>
            </div>
            <div class="bg-s1-bg rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-green-400 font-mono">{{ configuredVendorCount }}</div>
              <div class="text-s1-muted text-xs mt-0.5">Vendors</div>
            </div>
          </div>

          <div class="p-4 bg-s1-bg rounded-lg border border-s1-border/50 text-xs text-s1-muted space-y-1.5">
            <div class="font-semibold text-s1-subtle mb-1">How it works</div>
            <div><code class="text-s1-muted">off</code> &mdash; mock serves all responses normally</div>
            <div><code class="text-red-400">record</code> &mdash; requests are forwarded to the real vendor API, the exchange is saved, and the real response is returned</div>
            <div><code class="text-s1-primary">replay</code> &mdash; saved recordings are served by vendor + method + path; falls back to mock if no match</div>
            <div class="pt-1">&bull; Dev endpoints (<code class="text-s1-cyan">/_dev/*</code>) are always exempt</div>
            <div>&bull; Vendors without a configured base URL fall through to mock</div>
            <div>&bull; Recordings survive seed resets</div>
          </div>
        </div>
      </div>

      <!-- Per-vendor configuration -->
      <div v-if="showConnectionSettings" class="card">
        <div class="px-6 py-4 border-b border-s1-border">
          <h2 class="text-s1-text font-semibold">Vendor Connections</h2>
          <p class="text-s1-muted text-xs mt-0.5">Configure upstream credentials for each vendor you want to proxy</p>
        </div>

        <div class="divide-y divide-s1-border/50">
          <div v-for="v in vendorList" :key="v.vendor" class="px-6">
            <!-- Vendor header row -->
            <div
              class="flex items-center justify-between py-3 cursor-pointer"
              @click="toggleVendor(v.vendor)"
            >
              <div class="flex items-center gap-3">
                <input
                  type="checkbox"
                  :checked="vendorDrafts[v.vendor]?.enabled"
                  @click.stop="vendorDrafts[v.vendor].enabled = !vendorDrafts[v.vendor].enabled"
                  class="rounded border-s1-border text-s1-primary focus:ring-s1-primary"
                />
                <span class="text-s1-text text-sm font-medium">{{ v.label }}</span>
                <span
                  class="inline-block px-2 py-0.5 rounded text-[10px] font-mono font-semibold"
                  :class="vendorBadgeClass(v.vendor)"
                >{{ v.vendor }}</span>
                <span v-if="vendorDrafts[v.vendor]?.base_url" class="text-s1-muted text-xs font-mono truncate max-w-[200px]">
                  {{ vendorDrafts[v.vendor].base_url }}
                </span>
              </div>
              <component :is="vendorDrafts[v.vendor]?.expanded ? ChevronUp : ChevronDown" class="w-4 h-4 text-s1-muted" />
            </div>

            <!-- Expanded vendor config form -->
            <div v-if="vendorDrafts[v.vendor]?.expanded" class="pb-4 space-y-3">
              <div>
                <label class="block text-s1-text text-sm font-medium mb-1">Base URL</label>
                <input
                  v-model="vendorDrafts[v.vendor].base_url"
                  type="text"
                  :placeholder="v.vendor === 's1' ? 'https://tenant.sentinelone.net' : `https://api.${v.vendor}.example.com`"
                  class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text placeholder-s1-muted focus:outline-none focus:border-s1-primary"
                />
              </div>

              <div>
                <label class="block text-s1-text text-sm font-medium mb-1">
                  Auth Method: <span class="text-s1-muted font-normal">{{ authLabel(vendorDrafts[v.vendor].auth.type) }}</span>
                </label>
              </div>

              <!-- API Token auth (S1) -->
              <template v-if="vendorDrafts[v.vendor].auth.type === 'api_token'">
                <div>
                  <label class="block text-s1-text text-xs mb-1">API Token</label>
                  <input
                    v-model="vendorDrafts[v.vendor].auth.token"
                    type="password"
                    placeholder="Leave blank to keep existing"
                    class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text placeholder-s1-muted focus:outline-none focus:border-s1-primary"
                  />
                </div>
              </template>

              <!-- OAuth2 auth (CS, MDE, Sentinel, Graph) -->
              <template v-if="vendorDrafts[v.vendor].auth.type === 'oauth2'">
                <div>
                  <label class="block text-s1-text text-xs mb-1">Token URL</label>
                  <input
                    v-model="vendorDrafts[v.vendor].auth.token_url"
                    type="text"
                    placeholder="https://api.crowdstrike.com/oauth2/token"
                    class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text placeholder-s1-muted focus:outline-none focus:border-s1-primary"
                  />
                </div>
                <div class="grid grid-cols-2 gap-3">
                  <div>
                    <label class="block text-s1-text text-xs mb-1">Client ID</label>
                    <input
                      v-model="vendorDrafts[v.vendor].auth.client_id"
                      type="text"
                      placeholder="Client ID"
                      class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text placeholder-s1-muted focus:outline-none focus:border-s1-primary"
                    />
                  </div>
                  <div>
                    <label class="block text-s1-text text-xs mb-1">Client Secret</label>
                    <input
                      v-model="vendorDrafts[v.vendor].auth.client_secret"
                      type="password"
                      placeholder="Leave blank to keep existing"
                      class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text placeholder-s1-muted focus:outline-none focus:border-s1-primary"
                    />
                  </div>
                </div>
              </template>

              <!-- Basic Auth (Elastic, Splunk) -->
              <template v-if="vendorDrafts[v.vendor].auth.type === 'basic'">
                <div class="grid grid-cols-2 gap-3">
                  <div>
                    <label class="block text-s1-text text-xs mb-1">Username</label>
                    <input
                      v-model="vendorDrafts[v.vendor].auth.username"
                      type="text"
                      placeholder="Username"
                      class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text placeholder-s1-muted focus:outline-none focus:border-s1-primary"
                    />
                  </div>
                  <div>
                    <label class="block text-s1-text text-xs mb-1">Password</label>
                    <input
                      v-model="vendorDrafts[v.vendor].auth.password"
                      type="password"
                      placeholder="Leave blank to keep existing"
                      class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text placeholder-s1-muted focus:outline-none focus:border-s1-primary"
                    />
                  </div>
                </div>
                <div>
                  <label class="block text-s1-text text-xs mb-1">API Key <span class="text-s1-muted">(optional, overrides Basic Auth)</span></label>
                  <input
                    v-model="vendorDrafts[v.vendor].auth.api_key"
                    type="password"
                    placeholder="If set, uses ApiKey auth instead of Basic"
                    class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text placeholder-s1-muted focus:outline-none focus:border-s1-primary"
                  />
                </div>
              </template>

              <!-- HMAC auth (Cortex XDR) -->
              <template v-if="vendorDrafts[v.vendor].auth.type === 'hmac'">
                <div class="grid grid-cols-2 gap-3">
                  <div>
                    <label class="block text-s1-text text-xs mb-1">API Key ID</label>
                    <input
                      v-model="vendorDrafts[v.vendor].auth.key_id"
                      type="text"
                      placeholder="Key ID"
                      class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text placeholder-s1-muted focus:outline-none focus:border-s1-primary"
                    />
                  </div>
                  <div>
                    <label class="block text-s1-text text-xs mb-1">API Key Secret</label>
                    <input
                      v-model="vendorDrafts[v.vendor].auth.key_secret"
                      type="password"
                      placeholder="Leave blank to keep existing"
                      class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text placeholder-s1-muted focus:outline-none focus:border-s1-primary"
                    />
                  </div>
                </div>
              </template>
            </div>
          </div>
        </div>
      </div>

      <!-- Recordings table -->
      <div class="card">
        <div class="flex items-center justify-between px-6 py-4 border-b border-s1-border">
          <div class="flex items-center gap-3">
            <h2 class="text-s1-text font-semibold">
              Recordings
              <span class="ml-2 text-xs font-normal text-s1-muted">({{ filteredRecordings.length }} total, newest first)</span>
            </h2>
            <!-- Vendor filter -->
            <select
              v-model="recordingFilter"
              class="bg-s1-bg border border-s1-border rounded-lg px-2 py-1 text-xs text-s1-text focus:outline-none focus:border-s1-primary"
            >
              <option value="all">All vendors</option>
              <option v-for="v in vendorList" :key="v.vendor" :value="v.vendor">{{ v.label }}</option>
            </select>
          </div>
          <button
            v-if="recordings.length > 0"
            @click="clearRecordings"
            :disabled="clearing"
            class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-red-400 border border-red-400/30 hover:bg-red-500/10 transition-colors disabled:opacity-50"
          >
            <Trash2 class="w-3.5 h-3.5" />
            {{ clearing ? 'Clearing...' : 'Clear All' }}
          </button>
        </div>

        <div v-if="filteredRecordings.length === 0" class="px-6 py-10 text-center text-s1-muted text-sm">
          No recordings yet. Switch to <code class="text-red-400">record</code> mode and make some API calls.
        </div>

        <div v-else class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-s1-border text-s1-muted text-xs uppercase tracking-wider">
                <th class="px-6 py-3 text-left font-medium">Vendor</th>
                <th class="px-6 py-3 text-left font-medium">Method</th>
                <th class="px-6 py-3 text-left font-medium">Status</th>
                <th class="px-6 py-3 text-left font-medium">Path</th>
                <th class="px-6 py-3 text-left font-medium">Content-Type</th>
                <th class="px-6 py-3 text-left font-medium">Recorded At</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="rec in filteredRecordings"
                :key="rec.id"
                class="border-b border-s1-border/50 hover:bg-s1-hover/30 transition-colors"
              >
                <td class="px-6 py-3">
                  <span
                    class="inline-block px-2 py-0.5 rounded text-[10px] font-mono font-semibold"
                    :class="vendorBadgeClass(rec.vendor)"
                  >{{ rec.vendor }}</span>
                </td>
                <td class="px-6 py-3">
                  <span
                    class="inline-block px-2 py-0.5 rounded text-xs font-mono font-semibold"
                    :class="methodClass(rec.method)"
                  >{{ rec.method }}</span>
                </td>
                <td class="px-6 py-3">
                  <span
                    class="inline-block px-2 py-0.5 rounded text-xs font-mono font-semibold"
                    :class="statusClass(rec.response_status)"
                  >{{ rec.response_status }}</span>
                </td>
                <td class="px-6 py-3 font-mono text-s1-text text-xs max-w-xs truncate" :title="rec.path">
                  {{ rec.path }}
                  <span v-if="rec.query_string" class="text-s1-muted">?{{ rec.query_string }}</span>
                </td>
                <td class="px-6 py-3 text-s1-muted text-xs">{{ rec.response_content_type }}</td>
                <td class="px-6 py-3 text-s1-muted text-xs font-mono">{{ rec.recorded_at }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>
