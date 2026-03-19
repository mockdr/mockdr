<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { RefreshCw, Plus, Trash2 } from 'lucide-vue-next'
import { xdrHashExceptionsApi } from '../../api/cortex'
import type { XdrHashException } from '../../types/cortex'
import { formatEpoch } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const activeTab = ref<'blocklist' | 'allowlist'>('blocklist')
const blocklist = ref<XdrHashException[]>([])
const allowlist = ref<XdrHashException[]>([])

const showAddDialog = ref(false)
const newHash = ref('')
const newComment = ref('')

const currentList = computed(() =>
  activeTab.value === 'blocklist' ? blocklist.value : allowlist.value,
)

async function fetchData(): Promise<void> {
  loading.value = true
  try {
    const [bRes, aRes] = await Promise.all([
      xdrHashExceptionsApi.getBlocklist(),
      xdrHashExceptionsApi.getAllowlist(),
    ])
    blocklist.value = bRes.reply?.data ?? []
    allowlist.value = aRes.reply?.data ?? []
  } finally {
    loading.value = false
  }
}

async function addHash(): Promise<void> {
  if (!newHash.value.trim()) return
  const entry = { hash: newHash.value.trim(), comment: newComment.value.trim() }
  if (activeTab.value === 'blocklist') {
    await xdrHashExceptionsApi.addToBlocklist([entry])
  } else {
    await xdrHashExceptionsApi.addToAllowlist([entry])
  }
  newHash.value = ''
  newComment.value = ''
  showAddDialog.value = false
  await fetchData()
}

async function removeHash(hash: string): Promise<void> {
  if (activeTab.value === 'blocklist') {
    await xdrHashExceptionsApi.removeFromBlocklist([hash])
  } else {
    await xdrHashExceptionsApi.removeFromAllowlist([hash])
  }
  await fetchData()
}

onMounted(() => fetchData())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-orange-500 font-bold">XDR</span> Hash Exceptions
        </h1>
        <p class="text-s1-muted text-sm">Manage hash blocklist and allowlist for file verdict overrides</p>
      </div>
      <div class="flex items-center gap-2">
        <button @click="showAddDialog = !showAddDialog" class="btn-primary flex items-center gap-2 text-sm">
          <Plus class="w-3.5 h-3.5" />
          Add Hash
        </button>
        <button @click="fetchData()" class="btn-ghost flex items-center gap-2">
          <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
          Refresh
        </button>
      </div>
    </div>

    <!-- Add hash dialog -->
    <div v-if="showAddDialog" class="card p-4 space-y-3 border border-s1-primary/30">
      <div class="text-sm font-medium text-s1-text">
        Add to {{ activeTab === 'blocklist' ? 'Blocklist' : 'Allowlist' }}
      </div>
      <div class="flex flex-wrap gap-3">
        <input
          v-model="newHash"
          placeholder="SHA256 hash value"
          class="input flex-1 min-w-[300px] font-mono text-sm"
        />
        <input
          v-model="newComment"
          placeholder="Comment (optional)"
          class="input flex-1 min-w-[200px] text-sm"
        />
        <button @click="addHash()" :disabled="!newHash.trim()" class="btn-primary text-sm">
          Add
        </button>
        <button @click="showAddDialog = false" class="btn-ghost text-sm">
          Cancel
        </button>
      </div>
    </div>

    <!-- Tab toggle + table -->
    <div class="card overflow-hidden">
      <div class="flex border-b border-s1-border">
        <button
          @click="activeTab = 'blocklist'"
          class="px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px"
          :class="activeTab === 'blocklist'
            ? 'text-red-400 border-red-500'
            : 'text-s1-muted border-transparent hover:text-s1-text'"
        >
          Blocklist ({{ blocklist.length }})
        </button>
        <button
          @click="activeTab = 'allowlist'"
          class="px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px"
          :class="activeTab === 'allowlist'
            ? 'text-green-400 border-green-500'
            : 'text-s1-muted border-transparent hover:text-s1-text'"
        >
          Allowlist ({{ allowlist.length }})
        </button>
      </div>

      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Hash</th>
            <th class="table-header text-left">Comment</th>
            <th class="table-header text-left">Created</th>
            <th class="table-header text-right w-20">Actions</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !currentList.length" :rows="6" />
          <template v-else>
            <tr v-for="entry in currentList" :key="entry.exception_id" class="table-row">
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-text break-all">{{ entry.hash }}</span>
              </td>
              <td class="table-cell text-sm text-s1-subtle max-w-[300px] truncate">
                {{ entry.comment || '--' }}
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ formatEpoch(entry.created_at) }}</td>
              <td class="table-cell text-right">
                <button
                  @click="removeHash(entry.hash)"
                  class="p-1.5 rounded hover:bg-red-500/10 text-s1-muted hover:text-red-400 transition-colors"
                  title="Remove hash"
                >
                  <Trash2 class="w-3.5 h-3.5" />
                </button>
              </td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !currentList.length"
        icon="--"
        :title="`No ${activeTab} entries`"
        :description="`No hashes in the ${activeTab}. Click 'Add Hash' to create one.`"
      />
    </div>
  </div>
</template>
