<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Bell, ChevronDown, LogOut, User, X } from 'lucide-vue-next'
import { useAuthStore, PRESET_TOKENS } from '../../stores/auth'
import { alertsApi } from '../../api/alerts'
import type { Alert } from '../../types'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const showUserMenu = ref(false)
const showAlerts = ref(false)
const recentAlerts = ref<Alert[]>([])
const unreadCount = ref(0)
const alertsError = ref(false)

async function loadAlerts(): Promise<void> {
  alertsError.value = false
  try {
    const res = await alertsApi.list({ limit: 8, incidentStatuses: 'Unresolved' })
    recentAlerts.value = res.data
    unreadCount.value = res.pagination?.totalItems ?? res.data.length
  } catch {
    alertsError.value = true
  }
}

onMounted(loadAlerts)

function toggleAlerts(): void {
  showAlerts.value = !showAlerts.value
  if (showAlerts.value) loadAlerts()
}

const SEVERITY_DOT: Record<string, string> = {
  Critical: 'bg-s1-danger',
  High: 'bg-s1-warning',
  Medium: 'bg-yellow-400',
  Low: 'bg-s1-cyan',
  Info: 'bg-s1-muted',
}

const breadcrumb = computed(() => {
  const path = route.path.replace('/', '')
  return path.split('/').filter(Boolean).map((s) =>
    s.charAt(0).toUpperCase() + s.slice(1).replace(/-/g, ' ')
  )
})

const currentRole = computed(() => {
  const t = PRESET_TOKENS.find((t) => t.token === auth.token)
  return t?.role ?? 'User'
})

function switchToken(token: string): void {
  auth.login(token)
  showUserMenu.value = false
  router.go(0)
}

function logout(): void {
  auth.logout()
  router.push('/login')
}
</script>

<template>
  <header class="h-14 bg-s1-card border-b border-s1-border flex items-center px-6 gap-4 flex-shrink-0">
    <!-- Breadcrumb -->
    <nav aria-label="Breadcrumb" class="flex items-center gap-1.5 text-sm flex-1">
      <span class="text-s1-muted">Hypervisor</span>
      <template v-for="(crumb, i) in breadcrumb" :key="i">
        <span class="text-s1-muted">/</span>
        <span :class="i === breadcrumb.length - 1 ? 'text-s1-text font-medium' : 'text-s1-muted'">{{ crumb }}</span>
      </template>
    </nav>

    <!-- Notification bell -->
    <div class="relative">
      <button @click="toggleAlerts" aria-label="Toggle alerts" class="relative p-2 rounded-lg hover:bg-s1-hover transition-colors">
        <Bell class="w-4 h-4 text-s1-subtle" />
        <span v-if="unreadCount > 0" class="absolute top-1 right-1 min-w-[16px] h-4 px-0.5 bg-s1-danger rounded-full text-[9px] font-bold text-white flex items-center justify-center">
          {{ unreadCount > 99 ? '99+' : unreadCount }}
        </span>
      </button>

      <div
        v-if="showAlerts"
        class="absolute right-0 top-full mt-1 w-80 card shadow-xl z-50 overflow-hidden"
      >
        <div class="flex items-center justify-between px-4 py-2.5 border-b border-s1-border">
          <span class="text-sm font-semibold text-s1-text">Unresolved Alerts</span>
          <button @click="showAlerts = false" aria-label="Close alerts" class="text-s1-muted hover:text-s1-text">
            <X class="w-3.5 h-3.5" />
          </button>
        </div>
        <div v-if="alertsError" class="px-4 py-6 text-center text-s1-danger text-sm">
          Failed to load alerts
        </div>
        <div v-else-if="!recentAlerts.length" class="px-4 py-6 text-center text-s1-muted text-sm">
          No unresolved alerts
        </div>
        <div v-else class="divide-y divide-s1-border/50 max-h-72 overflow-y-auto">
          <div
            v-for="alert in recentAlerts" :key="alert.alertInfo.alertId"
            @click="router.push('/alerts'); showAlerts = false"
            class="px-4 py-3 hover:bg-s1-hover cursor-pointer transition-colors flex items-start gap-3"
          >
            <div class="flex-shrink-0 mt-1.5 w-2 h-2 rounded-full" :class="SEVERITY_DOT[alert.ruleInfo.severity] ?? 'bg-s1-muted'" />
            <div class="flex-1 min-w-0">
              <div class="text-sm text-s1-text font-medium truncate">{{ alert.ruleInfo.name }}</div>
              <div class="text-xs text-s1-muted">{{ alert.agentRealtimeInfo.agentComputerName }} · {{ alert.alertInfo.createdAt?.slice(0, 10) }}</div>
            </div>
            <span class="text-[10px] text-s1-muted flex-shrink-0 mt-0.5">{{ alert.ruleInfo.severity }}</span>
          </div>
        </div>
        <div class="px-4 py-2.5 border-t border-s1-border">
          <button @click="router.push('/alerts'); showAlerts = false" class="text-xs text-s1-primary hover:underline w-full text-center">
            View all alerts →
          </button>
        </div>
      </div>

      <div v-if="showAlerts" class="fixed inset-0 z-40" @click="showAlerts = false" />
    </div>

    <!-- User menu -->
    <div class="relative">
      <button
        @click="showUserMenu = !showUserMenu"
        aria-label="User menu"
        class="flex items-center gap-2 px-3 py-1.5 rounded-lg hover:bg-s1-hover transition-colors"
      >
        <div class="w-7 h-7 rounded-full bg-s1-primary/30 flex items-center justify-center">
          <User class="w-3.5 h-3.5 text-s1-primary" />
        </div>
        <span class="text-sm text-s1-text">{{ currentRole }}</span>
        <ChevronDown class="w-3.5 h-3.5 text-s1-muted" />
      </button>

      <div
        v-if="showUserMenu"
        class="absolute right-0 top-full mt-1 w-52 card shadow-xl z-50"
        @click.stop
      >
        <div class="p-3 border-b border-s1-border">
          <div class="text-xs text-s1-muted mb-2 font-semibold uppercase tracking-wide">Switch Role</div>
          <button
            v-for="t in PRESET_TOKENS"
            :key="t.token"
            @click="switchToken(t.token)"
            class="w-full text-left px-2 py-1.5 rounded text-sm hover:bg-s1-hover transition-colors flex items-center justify-between"
            :class="t.token === auth.token ? 'text-s1-primary' : 'text-s1-subtle'"
          >
            {{ t.label }}
            <span v-if="t.token === auth.token" class="w-1.5 h-1.5 rounded-full bg-s1-primary"></span>
          </button>
        </div>
        <button
          @click="logout"
          class="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-s1-danger hover:bg-s1-danger/10 transition-colors"
        >
          <LogOut class="w-3.5 h-3.5" />
          Sign Out
        </button>
      </div>
    </div>
  </header>

  <!-- Backdrop -->
  <div v-if="showUserMenu" class="fixed inset-0 z-40" @click="showUserMenu = false" />
</template>
