<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { Radio, RefreshCw, Save, Trash2 } from 'lucide-vue-next'
import { proxyApi } from '../api/system'
import type { ProxyConfig, ProxyRecording } from '../types'

const config = ref<ProxyConfig | null>(null)
const recordings = ref<ProxyRecording[]>([])
const loading = ref(true)
const saving = ref(false)
const clearing = ref(false)

const draftMode = ref<'off' | 'record' | 'replay'>('off')
const draftBaseUrl = ref('')
const draftApiToken = ref('')

async function fetchAll(): Promise<void> {
  loading.value = true
  try {
    const [cfgRes, recRes] = await Promise.all([
      proxyApi.getConfig(),
      proxyApi.listRecordings(),
    ])
    config.value = cfgRes.data
    draftMode.value = cfgRes.data.mode
    draftBaseUrl.value = cfgRes.data.base_url
    draftApiToken.value = ''
    recordings.value = recRes.data
  } finally {
    loading.value = false
  }
}

async function saveConfig(): Promise<void> {
  saving.value = true
  try {
    const payload: { mode: string; base_url?: string; api_token?: string } = { mode: draftMode.value }
    if (draftBaseUrl.value) payload.base_url = draftBaseUrl.value
    if (draftApiToken.value) payload.api_token = draftApiToken.value
    const res = await proxyApi.setConfig(payload)
    config.value = res.data
    draftMode.value = res.data.mode
    draftBaseUrl.value = res.data.base_url
    draftApiToken.value = ''
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

const showConnectionSettings = computed(() => draftMode.value !== 'off')

onMounted(() => fetchAll())
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Recording Proxy</h1>
        <p class="text-s1-muted text-sm">Record real S1 API exchanges or replay saved responses</p>
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
        <!-- Mode + connection settings panel -->
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

          <!-- Connection settings (shown when mode != off) -->
          <div v-if="showConnectionSettings" class="space-y-3 border-t border-s1-border pt-4">
            <div>
              <label class="block text-s1-text text-sm font-medium mb-1">Base URL</label>
              <input
                v-model="draftBaseUrl"
                type="text"
                placeholder="https://tenant.sentinelone.net/web/api/v2.1"
                class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text placeholder-s1-muted focus:outline-none focus:border-s1-primary"
              />
              <p class="text-s1-muted text-xs mt-1">Real S1 management console API URL</p>
            </div>
            <div>
              <label class="block text-s1-text text-sm font-medium mb-1">API Token</label>
              <input
                v-model="draftApiToken"
                type="password"
                placeholder="Leave blank to keep existing token"
                class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text placeholder-s1-muted focus:outline-none focus:border-s1-primary"
              />
              <p v-if="config?.api_token" class="text-s1-muted text-xs mt-1">
                Current: <code class="text-s1-cyan">{{ config.api_token ? '****' + config.api_token.slice(-4) : '(not set)' }}</code>
              </p>
            </div>
          </div>

          <button
            @click="saveConfig"
            :disabled="saving"
            class="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium text-white bg-s1-primary hover:bg-s1-primary-dark transition-colors disabled:opacity-50"
          >
            <Save class="w-4 h-4" />
            {{ saving ? 'Saving…' : 'Apply Configuration' }}
          </button>
        </div>

        <!-- Live stats + info panel -->
        <div class="card p-6 space-y-4">
          <h2 class="text-s1-text font-semibold">Live Status</h2>

          <div class="grid grid-cols-2 gap-3">
            <div class="bg-s1-bg rounded-lg p-3 text-center">
              <div
                class="text-2xl font-bold uppercase"
                :class="{
                  'text-s1-muted': config?.mode === 'off',
                  'text-red-400': config?.mode === 'record',
                  'text-s1-primary': config?.mode === 'replay',
                }"
              >
                {{ config?.mode ?? '—' }}
              </div>
              <div class="text-s1-muted text-xs mt-0.5">Mode</div>
            </div>
            <div class="bg-s1-bg rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-s1-cyan font-mono">{{ config?.recording_count ?? 0 }}</div>
              <div class="text-s1-muted text-xs mt-0.5">Recordings</div>
            </div>
          </div>

          <div class="p-4 bg-s1-bg rounded-lg border border-s1-border/50 text-xs text-s1-muted space-y-1.5">
            <div class="font-semibold text-s1-subtle mb-1">How it works</div>
            <div><code class="text-s1-muted">off</code> — mock serves all responses normally</div>
            <div><code class="text-red-400">record</code> — every request is forwarded to the real S1 tenant, the exchange is saved, and the real response is returned</div>
            <div><code class="text-s1-primary">replay</code> — saved recordings are served by method+path; falls back to mock if no match</div>
            <div class="pt-1">• Dev endpoints (<code class="text-s1-cyan">/_dev/*</code>) are always exempt</div>
            <div>• Recordings survive seed resets</div>
          </div>
        </div>
      </div>

      <!-- Recordings table -->
      <div class="card">
        <div class="flex items-center justify-between px-6 py-4 border-b border-s1-border">
          <h2 class="text-s1-text font-semibold">
            Recordings
            <span class="ml-2 text-xs font-normal text-s1-muted">({{ recordings.length }} total, newest first)</span>
          </h2>
          <button
            v-if="recordings.length > 0"
            @click="clearRecordings"
            :disabled="clearing"
            class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-red-400 border border-red-400/30 hover:bg-red-500/10 transition-colors disabled:opacity-50"
          >
            <Trash2 class="w-3.5 h-3.5" />
            {{ clearing ? 'Clearing…' : 'Clear All' }}
          </button>
        </div>

        <div v-if="recordings.length === 0" class="px-6 py-10 text-center text-s1-muted text-sm">
          No recordings yet. Switch to <code class="text-red-400">record</code> mode and make some API calls.
        </div>

        <div v-else class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-s1-border text-s1-muted text-xs uppercase tracking-wider">
                <th class="px-6 py-3 text-left font-medium">Method</th>
                <th class="px-6 py-3 text-left font-medium">Status</th>
                <th class="px-6 py-3 text-left font-medium">Path</th>
                <th class="px-6 py-3 text-left font-medium">Content-Type</th>
                <th class="px-6 py-3 text-left font-medium">Recorded At</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="rec in recordings"
                :key="rec.id"
                class="border-b border-s1-border/50 hover:bg-s1-hover/30 transition-colors"
              >
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
