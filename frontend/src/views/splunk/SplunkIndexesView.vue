<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Database, RefreshCw } from 'lucide-vue-next'
import { splunkIndexApi } from '../../api/splunk'
import type { SplunkIndex, SplunkEntry } from '../../types/splunk'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const loading = ref(true)
const error = ref('')
const indexes = ref<SplunkEntry<SplunkIndex>[]>([])

async function fetchIndexes(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const res = await splunkIndexApi.list()
    indexes.value = res.entry ?? []
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to fetch indexes'
  } finally {
    loading.value = false
  }
}

onMounted(fetchIndexes)
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <Database class="w-5 h-5 text-blue-400" />
          Splunk Indexes
        </h1>
        <p class="text-s1-muted text-sm">All Splunk indexes and their event counts</p>
      </div>
      <button @click="fetchIndexes()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <div v-if="error" class="card p-4 border-red-500/40 bg-red-500/10 text-red-400 text-sm">{{ error }}</div>

    <div class="card">
      <LoadingSkeleton v-if="loading" :rows="8" />
      <div v-else class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-s1-border">
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Index Name</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Event Count</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Size (MB)</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Data Type</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Status</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-s1-border">
            <tr v-for="idx in indexes" :key="idx.name" class="hover:bg-s1-hover">
              <td class="px-4 py-3 text-s1-text font-medium">{{ idx.name }}</td>
              <td class="px-4 py-3 text-s1-text">{{ idx.content.totalEventCount }}</td>
              <td class="px-4 py-3 text-s1-muted">{{ idx.content.currentDBSizeMB }}</td>
              <td class="px-4 py-3 text-s1-muted">{{ idx.content.datatype }}</td>
              <td class="px-4 py-3">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="idx.content.disabled ? 'bg-red-500/15 text-red-400' : 'bg-green-500/15 text-green-400'"
                >
                  {{ idx.content.disabled ? 'Disabled' : 'Active' }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
