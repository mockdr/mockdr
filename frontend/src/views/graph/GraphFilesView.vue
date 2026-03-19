<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw, Folder, FileText } from 'lucide-vue-next'
import { ensureGraphAuth, graphFilesApi, graphUsersApi } from '../../api/graph'
import type { GraphDriveItem, GraphSharePointSite } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const items = ref<GraphDriveItem[]>([])
const sites = ref<GraphSharePointSite[]>([])

function formatSize(bytes: number): string {
  if (!bytes) return '—'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let size = bytes
  while (size >= 1024 && i < units.length - 1) {
    size /= 1024
    i++
  }
  return `${size.toFixed(1)} ${units[i]}`
}

async function fetchData(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const usersRes = await graphUsersApi.list({ $top: 1 })
    const firstUser = usersRes.value?.[0]

    const [itemsRes, sitesRes] = await Promise.all([
      firstUser
        ? graphFilesApi.listChildren(`users/${firstUser.id}`, 'root', { $top: 50 })
        : Promise.resolve({ value: [] }),
      graphFilesApi.listSites({ $top: 50 }),
    ])
    items.value = itemsRes.value ?? []
    sites.value = sitesRes.value ?? []
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
          <span class="font-bold" style="color: #0078D4">Graph</span> Files
        </h1>
        <p class="text-s1-muted text-sm">OneDrive files and SharePoint sites</p>
      </div>
      <button @click="fetchData()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Drive Items -->
    <div class="card overflow-hidden">
      <div class="px-4 py-3 border-b border-s1-border">
        <h2 class="text-sm font-semibold text-s1-text">Drive Items</h2>
      </div>
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Name</th>
            <th class="table-header text-left">Type</th>
            <th class="table-header text-left">Size</th>
            <th class="table-header text-left">Modified</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !items.length" :rows="8" />
          <template v-else>
            <tr v-for="item in items" :key="item.id" class="table-row">
              <td class="table-cell">
                <div class="flex items-center gap-2">
                  <Folder v-if="item.folder" class="w-4 h-4 text-yellow-400 flex-shrink-0" />
                  <FileText v-else class="w-4 h-4 text-blue-400 flex-shrink-0" />
                  <span class="font-medium text-s1-text text-sm">{{ item.name }}</span>
                </div>
              </td>
              <td class="table-cell text-sm text-s1-subtle">
                {{ item.folder ? `Folder (${item.folder.childCount} items)` : (item.file?.mimeType ?? 'File') }}
              </td>
              <td class="table-cell text-sm text-s1-muted">{{ item.folder ? '—' : formatSize(item.size) }}</td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(item.lastModifiedDateTime) }}</td>
            </tr>
          </template>
        </tbody>
      </table>
      <EmptyState
        v-if="!loading && !items.length"
        icon="--"
        title="No files"
        description="No drive items available."
      />
    </div>

    <!-- SharePoint Sites -->
    <div class="card overflow-hidden">
      <div class="px-4 py-3 border-b border-s1-border">
        <h2 class="text-sm font-semibold text-s1-text">SharePoint Sites</h2>
      </div>
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Name</th>
            <th class="table-header text-left">URL</th>
            <th class="table-header text-left">Created</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !sites.length" :rows="3" />
          <template v-else>
            <tr v-for="site in sites" :key="site.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ site.displayName }}</div>
              </td>
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-muted">{{ site.webUrl }}</span>
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(site.createdDateTime) }}</td>
            </tr>
          </template>
        </tbody>
      </table>
      <EmptyState
        v-if="!loading && !sites.length"
        icon="--"
        title="No SharePoint sites"
        description="No SharePoint sites available."
      />
    </div>
  </div>
</template>
