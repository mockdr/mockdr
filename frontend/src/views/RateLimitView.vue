<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Gauge, RefreshCw, Save } from 'lucide-vue-next'
import { systemApi } from '../api/system'
import type { RateLimitConfig } from '../types'

const config = ref<RateLimitConfig | null>(null)
const loading = ref(true)
const saving = ref(false)

const draftEnabled = ref(false)
const draftRpm = ref(60)

async function fetchConfig(): Promise<void> {
  loading.value = true
  try {
    const res = await systemApi.getRateLimit()
    config.value = res.data
    draftEnabled.value = res.data.enabled
    draftRpm.value = res.data.requests_per_minute
  } finally {
    loading.value = false
  }
}

async function saveConfig(): Promise<void> {
  saving.value = true
  try {
    const res = await systemApi.setRateLimit({ enabled: draftEnabled.value, requests_per_minute: draftRpm.value })
    config.value = res.data
    draftEnabled.value = res.data.enabled
    draftRpm.value = res.data.requests_per_minute
  } finally {
    saving.value = false
  }
}

const RPM_PRESETS = [10, 30, 60, 120, 300, 600]

onMounted(() => fetchConfig())
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Rate-Limit Simulation</h1>
        <p class="text-s1-muted text-sm">Throttle API responses to test client resilience</p>
      </div>
      <button @click="fetchConfig" :disabled="loading" class="btn-ghost flex items-center gap-1.5 text-sm">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <div v-if="loading" class="card p-6 animate-pulse">
      <div class="h-4 bg-s1-hover rounded w-1/3 mb-4" />
      <div class="h-4 bg-s1-hover rounded w-2/3" />
    </div>

    <div v-else-if="config" class="grid md:grid-cols-2 gap-6">
      <!-- Control panel -->
      <div class="card p-6 space-y-5">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-s1-warning/15 flex items-center justify-center">
            <Gauge class="w-5 h-5 text-s1-warning" />
          </div>
          <div>
            <h2 class="text-s1-text font-semibold">Configuration</h2>
            <p class="text-s1-muted text-xs">Sliding-window per API token</p>
          </div>
        </div>

        <!-- Enable toggle -->
        <div class="flex items-center justify-between py-2 border-b border-s1-border">
          <div>
            <div class="text-s1-text text-sm font-medium">Rate Limiting Enabled</div>
            <div class="text-s1-muted text-xs">When off, all requests pass through unrestricted</div>
          </div>
          <button
            @click="draftEnabled = !draftEnabled"
            class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors"
            :class="draftEnabled ? 'bg-s1-primary' : 'bg-s1-hover'"
          >
            <span
              class="inline-block h-4 w-4 transform rounded-full bg-white transition-transform shadow"
              :class="draftEnabled ? 'translate-x-6' : 'translate-x-1'"
            />
          </button>
        </div>

        <!-- RPM slider -->
        <div class="space-y-3">
          <div class="flex items-center justify-between">
            <label class="text-s1-text text-sm font-medium">Requests per Minute</label>
            <span class="text-s1-primary font-bold font-mono text-lg">{{ draftRpm }}</span>
          </div>
          <input
            v-model.number="draftRpm"
            type="range" min="1" max="600" step="1"
            :disabled="!draftEnabled"
            class="w-full accent-s1-primary disabled:opacity-40"
          />
          <div class="flex flex-wrap gap-1.5">
            <button
              v-for="preset in RPM_PRESETS" :key="preset"
              @click="draftRpm = preset"
              :disabled="!draftEnabled"
              class="px-2.5 py-1 rounded text-xs transition-colors disabled:opacity-40"
              :class="draftRpm === preset
                ? 'bg-s1-primary text-white'
                : 'bg-s1-bg border border-s1-border text-s1-subtle hover:border-s1-primary/50'"
            >{{ preset }}/min</button>
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

      <!-- Live stats -->
      <div class="card p-6 space-y-4">
        <h2 class="text-s1-text font-semibold">Live Status</h2>

        <div class="grid grid-cols-2 gap-3">
          <div class="bg-s1-bg rounded-lg p-3 text-center">
            <div class="text-2xl font-bold" :class="config.enabled ? 'text-s1-warning' : 'text-s1-muted'">
              {{ config.enabled ? 'ON' : 'OFF' }}
            </div>
            <div class="text-s1-muted text-xs mt-0.5">Status</div>
          </div>
          <div class="bg-s1-bg rounded-lg p-3 text-center">
            <div class="text-2xl font-bold text-s1-primary font-mono">{{ config.requests_per_minute }}</div>
            <div class="text-s1-muted text-xs mt-0.5">req / min</div>
          </div>
          <div class="bg-s1-bg rounded-lg p-3 text-center col-span-2">
            <div class="text-2xl font-bold text-s1-cyan font-mono">{{ config.active_counters }}</div>
            <div class="text-s1-muted text-xs mt-0.5">Active token windows</div>
          </div>
        </div>

        <div class="p-4 bg-s1-bg rounded-lg border border-s1-border/50 text-xs text-s1-muted space-y-1">
          <div class="font-semibold text-s1-subtle mb-1">How it works</div>
          <div>• Sliding 60-second window per API token</div>
          <div>• Returns <code class="text-s1-warning">HTTP 429</code> when limit is exceeded</div>
          <div>• Dev endpoints (<code class="text-s1-cyan">/_dev/*</code>) are always exempt</div>
          <div>• Unauthenticated requests are not throttled</div>
        </div>
      </div>
    </div>
  </div>
</template>
