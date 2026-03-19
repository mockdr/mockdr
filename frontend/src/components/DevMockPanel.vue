<script setup lang="ts">
import { ref } from 'vue'
import { Bug, X, Copy, Check, RotateCcw } from 'lucide-vue-next'
import { systemApi } from '../api/system'
import { useAuthStore, PRESET_TOKENS } from '../stores/auth'
import { useRouter } from 'vue-router'
import type { SystemStats } from '../types'

const isOpen = ref(false)
const auth = useAuthStore()
const router = useRouter()
const stats = ref<SystemStats | null>(null)
const loading = ref(false)
const copiedToken = ref<string | null>(null)

interface Scenario { id: string; label: string; desc: string }

const SCENARIOS: Scenario[] = [
  { id: 'mass_infection',  label: '🦠 Mass Infection',    desc: 'Infect 20 random agents' },
  { id: 'apt_campaign',    label: '🎯 APT Campaign',       desc: 'Targeted attack on 10 agents' },
  { id: 'agent_offline',   label: '📴 Agents Offline',    desc: 'Take 30% of agents offline' },
  { id: 'quiet_day',       label: '✅ Quiet Day',          desc: 'Resolve all threats & heal agents' },
]

async function loadStats(): Promise<void> {
  try {
    const res = await systemApi.stats()
    stats.value = res.data
  } catch { /* server may not be running */ }
}

async function triggerScenario(scenario: string): Promise<void> {
  loading.value = true
  try {
    await systemApi.scenario(scenario)
    await loadStats()
    router.go(0)
  } finally {
    loading.value = false
  }
}

async function resetAll(): Promise<void> {
  loading.value = true
  try {
    await systemApi.reset()
    await loadStats()
    router.go(0)
  } finally {
    loading.value = false
  }
}

async function switchToken(token: string): Promise<void> {
  await auth.login(token)
  router.go(0)
}

function copyToken(token: string): void {
  navigator.clipboard.writeText(token)
  copiedToken.value = token
  setTimeout(() => (copiedToken.value = null), 2000)
}

function onOpen(): void {
  isOpen.value = true
  loadStats()
}
</script>

<template>
  <!-- Floating panel -->
  <div class="fixed bottom-4 right-4 z-50">
    <!-- Panel body -->
    <Transition name="panel">
      <div v-if="isOpen" class="card shadow-2xl w-80 mb-3 overflow-hidden">
        <!-- Header -->
        <div class="flex items-center justify-between px-4 py-3 border-b border-s1-border bg-s1-primary/10">
          <div class="flex items-center gap-2">
            <Bug class="w-4 h-4 text-s1-primary" />
            <span class="text-s1-primary font-semibold text-sm">DEV Mock Controls</span>
          </div>
          <button @click="isOpen = false" class="text-s1-muted hover:text-s1-text transition-colors">
            <X class="w-4 h-4" />
          </button>
        </div>

        <div class="p-4 space-y-4 max-h-[75vh] overflow-y-auto">
          <!-- Stats -->
          <div v-if="stats" class="grid grid-cols-3 gap-2">
            <div v-for="[k, v] in Object.entries(stats).slice(0, 6)" :key="k"
              class="bg-s1-bg rounded-lg p-2 text-center">
              <div class="text-s1-primary font-bold text-lg">{{ v }}</div>
              <div class="text-s1-muted text-[10px] capitalize">{{ k.replace('_', ' ') }}</div>
            </div>
          </div>

          <!-- Role switcher -->
          <div>
            <div class="text-xs font-semibold text-s1-muted uppercase tracking-wide mb-2">Active Role</div>
            <div class="space-y-1">
              <button
                v-for="t in PRESET_TOKENS" :key="t.token"
                @click="switchToken(t.token)"
                class="w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-colors"
                :class="t.token === auth.token
                  ? 'bg-s1-primary/20 text-s1-primary border border-s1-primary/40'
                  : 'bg-s1-bg text-s1-subtle hover:bg-s1-hover hover:text-s1-text'"
              >
                {{ t.label }}
                <span class="text-[10px] text-s1-muted font-mono">{{ t.role }}</span>
              </button>
            </div>
          </div>

          <!-- Scenarios -->
          <div>
            <div class="text-xs font-semibold text-s1-muted uppercase tracking-wide mb-2">Scenarios</div>
            <div class="space-y-1.5">
              <button
                v-for="s in SCENARIOS" :key="s.id"
                @click="triggerScenario(s.id)"
                :disabled="loading"
                class="w-full text-left px-3 py-2.5 rounded-lg bg-s1-bg hover:bg-s1-hover transition-colors text-sm disabled:opacity-50"
              >
                <div class="font-medium text-s1-text">{{ s.label }}</div>
                <div class="text-[11px] text-s1-muted">{{ s.desc }}</div>
              </button>
            </div>
          </div>

          <!-- API Tokens -->
          <div>
            <div class="text-xs font-semibold text-s1-muted uppercase tracking-wide mb-2">API Tokens</div>
            <div class="space-y-1.5">
              <div v-for="t in PRESET_TOKENS" :key="t.token" class="bg-s1-bg rounded-lg p-2.5">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs font-medium text-s1-text">{{ t.label }}</span>
                  <button
                    @click="copyToken(t.token)"
                    class="text-s1-muted hover:text-s1-primary transition-colors"
                    :title="`Copy ${t.label} token`"
                  >
                    <Check v-if="copiedToken === t.token" class="w-3.5 h-3.5 text-s1-success" />
                    <Copy v-else class="w-3.5 h-3.5" />
                  </button>
                </div>
                <code class="block text-[10px] text-s1-muted font-mono break-all">{{ t.token }}</code>
              </div>
            </div>
          </div>

          <!-- Base URL -->
          <div>
            <div class="text-xs font-semibold text-s1-muted uppercase tracking-wide mb-1">API Base URL</div>
            <div class="bg-s1-bg rounded p-2 flex items-center justify-between gap-2">
              <code class="text-[11px] text-s1-cyan font-mono">http://localhost:8001/web/api/v2.1</code>
              <button @click="copyToken('http://localhost:8001/web/api/v2.1')" class="text-s1-muted hover:text-s1-primary transition-colors flex-shrink-0">
                <Copy class="w-3 h-3" />
              </button>
            </div>
          </div>

          <!-- Reset -->
          <button
            @click="resetAll"
            :disabled="loading"
            class="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-s1-danger/10 hover:bg-s1-danger/20 text-s1-danger text-sm font-medium transition-colors disabled:opacity-50"
          >
            <RotateCcw class="w-4 h-4" :class="loading ? 'animate-spin' : ''" />
            Reset to Seed Data
          </button>
        </div>
      </div>
    </Transition>

    <!-- Toggle button -->
    <button
      @click="isOpen ? (isOpen = false) : onOpen()"
      class="ml-auto flex items-center justify-center w-12 h-12 rounded-full bg-s1-primary shadow-lg shadow-s1-primary/30 hover:bg-s1-primary-dark transition-colors"
      title="DEV Mock Controls"
    >
      <X v-if="isOpen" class="w-5 h-5 text-white" />
      <Bug v-else class="w-5 h-5 text-white" />
    </button>
  </div>
</template>

<style scoped>
.panel-enter-active, .panel-leave-active {
  transition: opacity 0.15s, transform 0.15s;
}
.panel-enter-from, .panel-leave-to {
  opacity: 0;
  transform: translateY(8px) scale(0.97);
}
</style>
