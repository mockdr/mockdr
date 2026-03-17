<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, Shield, ShieldOff, Search } from 'lucide-vue-next'
import { xdrEndpointsApi } from '../../api/cortex'
import type { XdrEndpoint } from '../../types/cortex'
import { formatEpoch } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const route = useRoute()
const router = useRouter()
const id = route.params['id'] as string

const endpoint = ref<XdrEndpoint | null>(null)
const loading = ref(true)
const actionLoading = ref(false)

function statusBadgeClass(status: string): string {
  switch ((status ?? '').toLowerCase()) {
    case 'connected': return 'bg-green-500/15 text-green-400'
    case 'disconnected': return 'bg-red-500/15 text-red-400'
    case 'lost': return 'bg-gray-500/15 text-gray-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function isolationBadgeClass(isolation: string): string {
  switch ((isolation ?? '').toLowerCase()) {
    case 'isolated': return 'bg-red-500/15 text-red-400'
    case 'unisolated':
    case 'not_isolated': return 'bg-green-500/15 text-green-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function performAction(action: 'isolate' | 'unisolate' | 'scan'): Promise<void> {
  if (!endpoint.value) return
  actionLoading.value = true
  try {
    if (action === 'isolate') {
      await xdrEndpointsApi.isolate(id)
    } else if (action === 'unisolate') {
      await xdrEndpointsApi.unisolate(id)
    } else {
      await xdrEndpointsApi.scan(id)
    }
    // Refresh endpoint data
    const res = await xdrEndpointsApi.list([{ field: 'endpoint_id', operator: 'in', value: [id] }])
    const eps = res.reply?.endpoints ?? []
    if (eps.length > 0) endpoint.value = eps[0]
  } finally {
    actionLoading.value = false
  }
}

onMounted(async () => {
  try {
    const res = await xdrEndpointsApi.list([{ field: 'endpoint_id', operator: 'in', value: [id] }])
    const eps = res.reply?.endpoints ?? []
    endpoint.value = eps.length > 0 ? eps[0] : null
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <!-- Back -->
    <button @click="router.push('/cortex-xdr/endpoints')" class="btn-ghost flex items-center gap-2 mb-4 -ml-2">
      <ArrowLeft class="w-4 h-4" /> XDR Endpoints
    </button>

    <div v-if="loading" class="card p-6"><LoadingSkeleton :rows="8" /></div>

    <div v-else-if="endpoint" class="grid grid-cols-3 gap-4">
      <!-- Left: Endpoint card -->
      <div class="card p-5 space-y-4">
        <div class="flex items-start gap-3">
          <div class="w-12 h-12 rounded-xl flex items-center justify-center text-lg font-bold bg-orange-500/20 text-orange-400">
            {{ (endpoint.os_type ?? '?').charAt(0).toUpperCase() }}
          </div>
          <div class="flex-1 min-w-0">
            <h2 class="text-lg font-bold text-s1-text truncate">{{ endpoint.endpoint_name }}</h2>
            <div class="flex items-center gap-2 mt-1">
              <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="statusBadgeClass(endpoint.endpoint_status)">
                {{ endpoint.endpoint_status }}
              </span>
              <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="isolationBadgeClass(endpoint.is_isolated)">
                {{ endpoint.is_isolated || 'N/A' }}
              </span>
            </div>
          </div>
        </div>

        <!-- Actions -->
        <div class="flex flex-wrap gap-2">
          <button @click="performAction('isolate')" :disabled="actionLoading" class="btn-ghost flex items-center gap-1.5 text-xs">
            <Shield class="w-3.5 h-3.5" /> Isolate
          </button>
          <button @click="performAction('unisolate')" :disabled="actionLoading" class="btn-ghost flex items-center gap-1.5 text-xs">
            <ShieldOff class="w-3.5 h-3.5" /> Unisolate
          </button>
          <button @click="performAction('scan')" :disabled="actionLoading" class="btn-ghost flex items-center gap-1.5 text-xs">
            <Search class="w-3.5 h-3.5" /> Scan
          </button>
        </div>

        <div class="space-y-2 text-sm">
          <div v-for="[k, v] in [
            ['Endpoint ID', endpoint.endpoint_id],
            ['Endpoint Name', endpoint.endpoint_name],
            ['Endpoint Type', endpoint.endpoint_type],
            ['OS Type', endpoint.os_type],
            ['Status', endpoint.endpoint_status],
            ['Operational Status', endpoint.operational_status],
            ['Isolation', endpoint.is_isolated],
            ['Domain', endpoint.domain],
            ['Alias', endpoint.alias],
            ['IP', Array.isArray(endpoint.ip) ? endpoint.ip.join(', ') : endpoint.ip],
            ['Group', endpoint.group_name],
            ['Agent Version', endpoint.endpoint_version],
            ['Content Version', endpoint.content_version],
            ['First Seen', formatEpoch(endpoint.first_seen)],
            ['Last Seen', formatEpoch(endpoint.last_seen)],
            ['Install Date', formatEpoch(endpoint.install_date)],
          ]" :key="(k as string)" class="flex justify-between gap-2">
            <span class="text-s1-muted">{{ k }}</span>
            <span class="text-s1-text text-right truncate max-w-[60%] font-mono text-xs">{{ v ?? '--' }}</span>
          </div>
        </div>
      </div>

      <!-- Right: Details -->
      <div class="col-span-2 card overflow-hidden">
        <div class="px-5 py-4 border-b border-s1-border">
          <h3 class="text-sm font-semibold text-s1-text">Endpoint Details</h3>
        </div>

        <div class="p-5 overflow-y-auto max-h-[70vh]">
          <div class="space-y-5">
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">Endpoint Information</div>
              <div class="grid grid-cols-2 gap-x-6 gap-y-0 text-sm">
                <div v-for="[k, v] in [
                  ['Endpoint ID', endpoint.endpoint_id],
                  ['Endpoint Name', endpoint.endpoint_name],
                  ['Endpoint Type', endpoint.endpoint_type],
                  ['OS Type', endpoint.os_type],
                  ['Status', endpoint.endpoint_status],
                  ['Operational Status', endpoint.operational_status],
                  ['Isolation Status', endpoint.is_isolated],
                  ['Domain', endpoint.domain],
                  ['Alias', endpoint.alias || '--'],
                  ['Group Name', endpoint.group_name || '--'],
                  ['Agent Version', endpoint.endpoint_version],
                  ['Content Version', endpoint.content_version],
                  ['First Seen', formatEpoch(endpoint.first_seen)],
                  ['Last Seen', formatEpoch(endpoint.last_seen)],
                  ['Install Date', formatEpoch(endpoint.install_date)],
                ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
                  <span class="text-s1-muted shrink-0">{{ k }}</span>
                  <span class="text-s1-text font-mono text-xs truncate max-w-[55%] text-right">{{ v ?? '--' }}</span>
                </div>
              </div>
            </div>

            <div v-if="Array.isArray(endpoint.ip) && endpoint.ip.length">
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">IP Addresses</div>
              <div class="flex flex-wrap gap-2">
                <span v-for="ip in endpoint.ip" :key="ip"
                  class="text-xs px-2 py-0.5 rounded-full bg-orange-500/20 text-orange-400 font-mono">
                  {{ ip }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="card p-10 text-center">
      <p class="text-s1-muted">Endpoint not found</p>
      <button @click="router.push('/cortex-xdr/endpoints')" class="btn-ghost mt-4 text-sm">Back to endpoints</button>
    </div>
  </div>
</template>
