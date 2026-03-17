<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Zap, RefreshCw, Send } from 'lucide-vue-next'
import { splunkHecApi } from '../../api/splunk'
import type { SplunkHecToken, SplunkEntry } from '../../types/splunk'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const loading = ref(true)
const error = ref('')
const tokens = ref<SplunkEntry<SplunkHecToken>[]>([])
const healthStatus = ref('')

const testToken = ref('')
const testEvent = ref('{"message": "Test event from MockDR", "severity": "info"}')
const submitResult = ref('')

async function fetchTokens(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [tokenRes, healthRes] = await Promise.all([
      splunkHecApi.listTokens(),
      splunkHecApi.health(),
    ])
    tokens.value = tokenRes.entry ?? []
    healthStatus.value = healthRes.text ?? 'Unknown'
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to fetch HEC data'
  } finally {
    loading.value = false
  }
}

async function submitTestEvent(): Promise<void> {
  if (!testToken.value) {
    submitResult.value = 'Select a token first'
    return
  }
  try {
    const event = JSON.parse(testEvent.value)
    const res = await splunkHecApi.submitEvent(testToken.value, event)
    submitResult.value = `✓ ${res.text} (code: ${res.code})`
  } catch (e: unknown) {
    submitResult.value = e instanceof Error ? e.message : 'Failed to submit event'
  }
}

onMounted(fetchTokens)
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <Zap class="w-5 h-5 text-yellow-400" />
          HTTP Event Collector
        </h1>
        <p class="text-s1-muted text-sm">HEC token management and event submission</p>
      </div>
      <div class="flex items-center gap-3">
        <span class="text-xs px-2 py-1 rounded" :class="healthStatus === 'HEC is healthy' ? 'bg-green-500/15 text-green-400' : 'bg-yellow-500/15 text-yellow-400'">
          {{ healthStatus }}
        </span>
        <button @click="fetchTokens()" class="btn-ghost flex items-center gap-2">
          <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
          Refresh
        </button>
      </div>
    </div>

    <div v-if="error" class="card p-4 border-red-500/40 bg-red-500/10 text-red-400 text-sm">{{ error }}</div>

    <!-- Token list -->
    <div class="card">
      <div class="px-5 py-4 border-b border-s1-border">
        <h3 class="text-sm font-semibold text-s1-text">HEC Tokens</h3>
      </div>
      <LoadingSkeleton v-if="loading" :rows="4" />
      <div v-else class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-s1-border">
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Name</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Token</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Index</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Sourcetype</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Status</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-s1-border">
            <tr v-for="t in tokens" :key="t.name" class="hover:bg-s1-hover">
              <td class="px-4 py-3 text-s1-text font-medium">{{ t.name }}</td>
              <td class="px-4 py-3 text-s1-muted font-mono text-xs">{{ t.content.token }}</td>
              <td class="px-4 py-3 text-s1-text">{{ t.content.index }}</td>
              <td class="px-4 py-3 text-s1-muted">{{ t.content.sourcetype || '—' }}</td>
              <td class="px-4 py-3">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="t.content.disabled ? 'bg-red-500/15 text-red-400' : 'bg-green-500/15 text-green-400'">
                  {{ t.content.disabled ? 'Disabled' : 'Active' }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Test event submission -->
    <div class="card p-5 space-y-4">
      <h3 class="text-sm font-semibold text-s1-text">Submit Test Event</h3>
      <div class="grid grid-cols-2 gap-4">
        <div>
          <label class="block text-xs text-s1-muted mb-1">Token</label>
          <select v-model="testToken" class="w-full bg-s1-input border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text">
            <option value="">Select token...</option>
            <option v-for="t in tokens" :key="t.name" :value="t.content.token">
              {{ t.name }} ({{ t.content.index }})
            </option>
          </select>
        </div>
        <div>
          <label class="block text-xs text-s1-muted mb-1">Event JSON</label>
          <input v-model="testEvent" class="w-full bg-s1-input border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text font-mono" />
        </div>
      </div>
      <div class="flex items-center gap-3">
        <button @click="submitTestEvent" class="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 text-white rounded-lg text-sm flex items-center gap-2">
          <Send class="w-3.5 h-3.5" /> Submit
        </button>
        <span v-if="submitResult" class="text-sm text-s1-muted">{{ submitResult }}</span>
      </div>
    </div>
  </div>
</template>
