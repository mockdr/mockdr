<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, Wifi } from 'lucide-vue-next'
import { ensureCsAuth, csHostsApi } from '../../api/crowdstrike'
import type { CsHost } from '../../types/crowdstrike'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const route = useRoute()
const router = useRouter()
const id = route.params['id'] as string

const host = ref<CsHost | null>(null)
const loading = ref(true)
const activeTab = ref('overview')

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'network', label: 'Network' },
  { id: 'system', label: 'System' },
]

function platformColor(platform: string): string {
  switch (platform) {
    case 'Windows': return 'bg-red-500/20 text-red-400'
    case 'Mac': return 'bg-orange-500/20 text-orange-400'
    case 'Linux': return 'bg-yellow-500/20 text-yellow-400'
    default: return 'bg-gray-500/20 text-gray-400'
  }
}

onMounted(async () => {
  try {
    await ensureCsAuth()
    const res = await csHostsApi.getEntities([id])
    if (res.resources.length > 0) {
      host.value = res.resources[0]
    }
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <!-- Back -->
    <button @click="router.push('/crowdstrike/hosts')" class="btn-ghost flex items-center gap-2 mb-4 -ml-2">
      <ArrowLeft class="w-4 h-4" /> CS Hosts
    </button>

    <div v-if="loading" class="card p-6"><LoadingSkeleton :rows="8" /></div>

    <div v-else-if="host" class="grid grid-cols-3 gap-4">
      <!-- Left: Host card -->
      <div class="card p-5 space-y-4">
        <div class="flex items-start gap-3">
          <div
            class="w-12 h-12 rounded-xl flex items-center justify-center text-lg font-bold"
            :class="platformColor(host.platform_name)"
          >
            {{ host.platform_name?.charAt(0) ?? '?' }}
          </div>
          <div class="flex-1 min-w-0">
            <h2 class="text-lg font-bold text-s1-text truncate">{{ host.hostname }}</h2>
            <div class="flex items-center gap-2 mt-1">
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="{
                  'bg-green-500/15 text-green-400': host.status === 'normal',
                  'bg-red-500/15 text-red-400': host.status === 'contained',
                  'bg-yellow-500/15 text-yellow-400': host.status !== 'normal' && host.status !== 'contained',
                }"
              >
                {{ host.status }}
              </span>
              <span class="text-xs text-s1-muted">{{ host.platform_name }}</span>
            </div>
          </div>
        </div>

        <div class="space-y-2 text-sm">
          <div v-for="[k, v] in [
            ['Platform', host.platform_name],
            ['OS Version', host.os_version],
            ['Agent Version', host.agent_version],
            ['Device ID', host.device_id],
            ['CID', host.cid],
            ['Local IP', host.local_ip],
            ['External IP', host.external_ip],
            ['MAC Address', host.mac_address],
            ['Domain', host.machine_domain],
            ['Type', host.product_type_desc],
            ['Serial', host.serial_number],
            ['First Seen', host.first_seen?.slice(0, 10)],
            ['Last Seen', host.last_seen?.slice(0, 10)],
          ]" :key="(k as string)" class="flex justify-between gap-2">
            <span class="text-s1-muted">{{ k }}</span>
            <span class="text-s1-text text-right truncate max-w-[60%] font-mono text-xs">{{ v ?? '--' }}</span>
          </div>

          <!-- Tags -->
          <div v-if="host.tags?.length" class="pt-2">
            <div class="text-s1-muted text-xs mb-1.5">Tags</div>
            <div class="flex flex-wrap gap-1">
              <span v-for="tag in host.tags" :key="tag"
                class="text-xs px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 font-medium">
                {{ tag }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Right: Tabs -->
      <div class="col-span-2 card overflow-hidden">
        <!-- Tab nav -->
        <div class="flex border-b border-s1-border overflow-x-auto">
          <button
            v-for="tab in TABS" :key="tab.id"
            @click="activeTab = tab.id"
            class="px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px whitespace-nowrap"
            :class="activeTab === tab.id
              ? 'text-red-400 border-red-500'
              : 'text-s1-muted border-transparent hover:text-s1-text'"
          >
            {{ tab.label }}
          </button>
        </div>

        <div class="p-5 overflow-y-auto max-h-[70vh]">

          <!-- Overview -->
          <div v-if="activeTab === 'overview'" class="space-y-5">
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">Device Information</div>
              <div class="grid grid-cols-2 gap-x-6 gap-y-0 text-sm">
                <div v-for="[k, v] in [
                  ['Hostname', host.hostname],
                  ['Device ID', host.device_id],
                  ['CID', host.cid],
                  ['Platform', host.platform_name],
                  ['OS Version', host.os_version],
                  ['Agent Version', host.agent_version],
                  ['Product Type', host.product_type_desc],
                  ['Chassis Type', host.chassis_type],
                  ['Serial Number', host.serial_number],
                  ['Status', host.status],
                  ['Provision Status', host.provision_status],
                  ['Reduced Functionality', host.reduced_functionality_mode],
                  ['Detection Suppression', host.detection_suppression_status],
                  ['Modified', host.modified_timestamp?.slice(0, 19)],
                ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
                  <span class="text-s1-muted shrink-0">{{ k }}</span>
                  <span class="text-s1-text font-mono text-xs truncate max-w-[55%] text-right">{{ v ?? '--' }}</span>
                </div>
              </div>
            </div>

            <!-- Groups -->
            <div v-if="host.groups?.length">
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">Host Groups</div>
              <div class="flex flex-wrap gap-1.5">
                <span v-for="g in host.groups" :key="g"
                  class="text-xs font-mono px-2 py-1 rounded bg-s1-bg text-s1-text">
                  {{ g }}
                </span>
              </div>
            </div>
          </div>

          <!-- Network -->
          <div v-else-if="activeTab === 'network'" class="space-y-4 text-sm">
            <div class="rounded-lg border border-s1-border p-4 space-y-2">
              <div class="font-semibold text-s1-text flex items-center gap-2">
                <Wifi class="w-4 h-4 text-red-400" />
                Network Configuration
              </div>
              <div class="grid grid-cols-2 gap-x-6 gap-y-0">
                <div v-for="[k, v] in [
                  ['Local IP', host.local_ip],
                  ['External IP', host.external_ip],
                  ['MAC Address', host.mac_address],
                  ['Domain', host.machine_domain],
                  ['Site Name', host.site_name],
                ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
                  <span class="text-s1-muted shrink-0">{{ k }}</span>
                  <span class="text-s1-text font-mono text-xs truncate max-w-[55%] text-right">{{ v ?? '--' }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- System -->
          <div v-else-if="activeTab === 'system'" class="space-y-5">
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">System Hardware</div>
              <div class="grid grid-cols-2 gap-x-6 gap-y-0 text-sm">
                <div v-for="[k, v] in [
                  ['Manufacturer', host.system_manufacturer],
                  ['Product Name', host.system_product_name],
                  ['Chassis Type', host.chassis_type],
                  ['Serial Number', host.serial_number],
                  ['Platform ID', host.platform_id],
                ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
                  <span class="text-s1-muted shrink-0">{{ k }}</span>
                  <span class="text-s1-text font-mono text-xs truncate max-w-[55%] text-right">{{ v ?? '--' }}</span>
                </div>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>

    <div v-else class="card p-10 text-center">
      <p class="text-s1-muted">Host not found</p>
      <button @click="router.push('/crowdstrike/hosts')" class="btn-ghost mt-4 text-sm">Back to hosts</button>
    </div>
  </div>
</template>
