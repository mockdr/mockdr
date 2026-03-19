<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphMailApi, graphUsersApi } from '../../api/graph'
import type { GraphMailMessage, GraphMailFolder } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const folders = ref<GraphMailFolder[]>([])
const messages = ref<GraphMailMessage[]>([])
const selectedFolder = ref<string | null>(null)
const userId = ref<string>('')

async function fetchData(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    // Get the first user to use as mail context
    const usersRes = await graphUsersApi.list({ $top: 1 })
    const firstUser = usersRes.value?.[0]
    if (!firstUser) return
    userId.value = `users/${firstUser.id}`

    const [foldersRes, messagesRes] = await Promise.all([
      graphMailApi.listFolders(userId.value, { $top: 50 }),
      graphMailApi.listMessages(userId.value, { $top: 50 }),
    ])
    folders.value = foldersRes.value ?? []
    messages.value = messagesRes.value ?? []
  } finally {
    loading.value = false
  }
}

function selectFolder(folderId: string): void {
  selectedFolder.value = folderId
}

onMounted(() => fetchData())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Mail
        </h1>
        <p class="text-s1-muted text-sm">User mailbox folders and messages</p>
      </div>
      <button @click="fetchData()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <div class="flex gap-4">
      <!-- Folders Sidebar -->
      <div class="card w-64 flex-shrink-0 overflow-hidden">
        <div class="px-4 py-3 border-b border-s1-border">
          <h2 class="text-sm font-semibold text-s1-text">Folders</h2>
        </div>
        <LoadingSkeleton v-if="loading && !folders.length" :rows="5" />
        <div v-else class="py-1">
          <button
            v-for="folder in folders" :key="folder.id"
            @click="selectFolder(folder.id)"
            class="w-full text-left px-4 py-2 text-sm transition-colors duration-150 flex items-center justify-between"
            :class="selectedFolder === folder.id
              ? 'bg-s1-primary/15 text-s1-primary font-medium'
              : 'text-s1-subtle hover:text-s1-text hover:bg-s1-hover'"
          >
            <span>{{ folder.displayName }}</span>
            <span class="text-xs text-s1-muted">
              {{ folder.unreadItemCount > 0 ? folder.unreadItemCount : '' }}
            </span>
          </button>
          <div v-if="!folders.length" class="px-4 py-3 text-sm text-s1-muted">No folders</div>
        </div>
      </div>

      <!-- Messages List -->
      <div class="card flex-1 overflow-hidden">
        <div class="px-4 py-3 border-b border-s1-border">
          <h2 class="text-sm font-semibold text-s1-text">Messages</h2>
        </div>
        <table class="w-full">
          <thead class="border-b border-s1-border">
            <tr>
              <th class="table-header text-left">Subject</th>
              <th class="table-header text-left">From</th>
              <th class="table-header text-left">Received</th>
              <th class="table-header text-left">Status</th>
            </tr>
          </thead>
          <tbody>
            <LoadingSkeleton v-if="loading && !messages.length" :rows="8" />
            <template v-else>
              <tr v-for="msg in messages" :key="msg.id" class="table-row">
                <td class="table-cell">
                  <div class="font-medium text-s1-text text-sm" :class="{ 'font-bold': !msg.isRead }">
                    {{ msg.subject }}
                  </div>
                  <div class="text-xs text-s1-muted truncate max-w-[300px]">{{ msg.bodyPreview }}</div>
                </td>
                <td class="table-cell text-sm text-s1-subtle">
                  {{ msg.from?.emailAddress?.name ?? '—' }}
                </td>
                <td class="table-cell text-xs text-s1-muted">{{ relativeTime(msg.receivedDateTime) }}</td>
                <td class="table-cell">
                  <span
                    class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                    :class="msg.isRead
                      ? 'bg-gray-500/15 text-gray-400'
                      : 'bg-blue-500/15 text-blue-400'"
                  >
                    {{ msg.isRead ? 'Read' : 'Unread' }}
                  </span>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
        <EmptyState
          v-if="!loading && !messages.length"
          icon="--"
          title="No messages"
          description="No mail messages available."
        />
      </div>
    </div>
  </div>
</template>
