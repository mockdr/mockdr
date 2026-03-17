<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { RefreshCw, Plus, Trash2 } from 'lucide-vue-next'
import { esExceptionListsApi } from '../../api/elastic'
import type { EsExceptionList, EsExceptionListItem } from '../../types/elastic'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const lists = ref<EsExceptionList[]>([])
const items = ref<EsExceptionListItem[]>([])
const selectedListId = ref('')

// Create list dialog
const showCreateList = ref(false)
const newList = ref({ name: '', description: '', type: 'detection' })

// Create item dialog
const showCreateItem = ref(false)
const newItem = ref({
  name: '',
  description: '',
  field: '',
  operator: 'included',
  value: '',
})

async function fetchLists(): Promise<void> {
  loading.value = true
  try {
    const res = await esExceptionListsApi.findLists({ per_page: 100 })
    lists.value = res.data ?? []
    if (lists.value.length > 0 && !selectedListId.value) {
      selectedListId.value = lists.value[0].id
    }
  } finally {
    loading.value = false
  }
}

async function fetchItems(): Promise<void> {
  if (!selectedListId.value) {
    items.value = []
    return
  }
  loading.value = true
  try {
    const list = lists.value.find(l => l.id === selectedListId.value)
    const res = await esExceptionListsApi.findItems({
      list_id: list?.list_id ?? selectedListId.value,
      namespace_type: list?.namespace_type ?? 'single',
      per_page: 100,
    })
    items.value = res.data ?? []
  } finally {
    loading.value = false
  }
}

async function createList(): Promise<void> {
  loading.value = true
  try {
    await esExceptionListsApi.createList({
      name: newList.value.name,
      description: newList.value.description,
      type: newList.value.type,
      namespace_type: 'single',
    })
    showCreateList.value = false
    newList.value = { name: '', description: '', type: 'detection' }
    await fetchLists()
  } finally {
    loading.value = false
  }
}

async function deleteList(id: string, namespaceType: string): Promise<void> {
  loading.value = true
  try {
    await esExceptionListsApi.deleteList(id, namespaceType)
    if (selectedListId.value === id) selectedListId.value = ''
    await fetchLists()
  } finally {
    loading.value = false
  }
}

async function createItem(): Promise<void> {
  if (!selectedListId.value) return
  const list = lists.value.find(l => l.id === selectedListId.value)
  loading.value = true
  try {
    await esExceptionListsApi.createItem({
      list_id: list?.list_id ?? selectedListId.value,
      namespace_type: list?.namespace_type ?? 'single',
      name: newItem.value.name,
      description: newItem.value.description,
      type: 'simple',
      entries: [{
        field: newItem.value.field,
        operator: newItem.value.operator,
        type: 'match',
        value: newItem.value.value,
      }],
    })
    showCreateItem.value = false
    newItem.value = { name: '', description: '', field: '', operator: 'included', value: '' }
    await fetchItems()
  } finally {
    loading.value = false
  }
}

async function deleteItem(id: string): Promise<void> {
  const list = lists.value.find(l => l.id === selectedListId.value)
  loading.value = true
  try {
    await esExceptionListsApi.deleteItem(id, list?.namespace_type ?? 'single')
    await fetchItems()
  } finally {
    loading.value = false
  }
}

watch(selectedListId, () => fetchItems())

onMounted(async () => {
  await fetchLists()
  if (selectedListId.value) await fetchItems()
})
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-purple-500 font-bold">ES</span> Exception Lists
        </h1>
        <p class="text-s1-muted text-sm">Manage detection exception lists and items</p>
      </div>
      <button @click="fetchLists()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Create list dialog -->
    <div v-if="showCreateList" class="card p-5 border-purple-500/40 space-y-4">
      <h3 class="text-sm font-semibold text-s1-text">Create Exception List</h3>
      <div class="grid grid-cols-3 gap-4">
        <div>
          <label class="text-xs text-s1-muted">Name</label>
          <input v-model="newList.name" class="input mt-1" placeholder="List name" />
        </div>
        <div>
          <label class="text-xs text-s1-muted">Description</label>
          <input v-model="newList.description" class="input mt-1" placeholder="Description" />
        </div>
        <div>
          <label class="text-xs text-s1-muted">Type</label>
          <select v-model="newList.type" class="select mt-1">
            <option value="detection">Detection</option>
            <option value="endpoint">Endpoint</option>
          </select>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <button @click="createList()" :disabled="!newList.name || loading"
          class="btn-ghost text-purple-400 text-sm">Create</button>
        <button @click="showCreateList = false" class="btn-ghost text-sm">Cancel</button>
      </div>
    </div>

    <!-- Two-panel layout -->
    <div class="grid grid-cols-3 gap-4">
      <!-- Left: Lists -->
      <div class="card overflow-hidden">
        <div class="flex items-center justify-between px-4 py-3 border-b border-s1-border">
          <h3 class="text-sm font-semibold text-s1-text">Lists</h3>
          <button @click="showCreateList = true" class="btn-ghost p-1 text-purple-400">
            <Plus class="w-3.5 h-3.5" />
          </button>
        </div>
        <LoadingSkeleton v-if="loading && !lists.length" :rows="5" />
        <div v-else class="divide-y divide-s1-border">
          <div
            v-for="list in lists" :key="list.id"
            class="px-4 py-3 cursor-pointer transition-colors flex items-center justify-between"
            :class="selectedListId === list.id ? 'bg-purple-500/10' : 'hover:bg-s1-hover'"
            @click="selectedListId = list.id"
          >
            <div class="min-w-0 flex-1">
              <div class="text-sm text-s1-text font-medium truncate">{{ list.name }}</div>
              <div class="text-xs text-s1-muted">{{ list.type }} | {{ list.total_items ?? 0 }} items</div>
            </div>
            <button @click.stop="deleteList(list.id, list.namespace_type)" class="btn-ghost p-1 text-red-400 ml-2 shrink-0">
              <Trash2 class="w-3 h-3" />
            </button>
          </div>
        </div>
        <div v-if="!loading && !lists.length" class="py-8 text-center text-s1-muted text-sm">
          No exception lists
        </div>
      </div>

      <!-- Right: Items -->
      <div class="col-span-2 card overflow-hidden">
        <div class="flex items-center justify-between px-4 py-3 border-b border-s1-border">
          <h3 class="text-sm font-semibold text-s1-text">
            Items
            <span v-if="selectedListId" class="text-s1-muted font-normal">
              ({{ items.length }})
            </span>
          </h3>
          <button v-if="selectedListId" @click="showCreateItem = true" class="btn-ghost p-1 text-purple-400">
            <Plus class="w-3.5 h-3.5" />
          </button>
        </div>

        <!-- Create item dialog -->
        <div v-if="showCreateItem" class="p-4 border-b border-s1-border space-y-3">
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-xs text-s1-muted">Name</label>
              <input v-model="newItem.name" class="input mt-1" placeholder="Item name" />
            </div>
            <div>
              <label class="text-xs text-s1-muted">Description</label>
              <input v-model="newItem.description" class="input mt-1" placeholder="Description" />
            </div>
            <div>
              <label class="text-xs text-s1-muted">Field</label>
              <input v-model="newItem.field" class="input mt-1" placeholder="e.g. process.name" />
            </div>
            <div>
              <label class="text-xs text-s1-muted">Value</label>
              <input v-model="newItem.value" class="input mt-1" placeholder="Match value" />
            </div>
          </div>
          <div class="flex items-center gap-2">
            <button @click="createItem()" :disabled="!newItem.name || !newItem.field || !newItem.value || loading"
              class="btn-ghost text-purple-400 text-sm">Create</button>
            <button @click="showCreateItem = false" class="btn-ghost text-sm">Cancel</button>
          </div>
        </div>

        <div v-if="!selectedListId" class="py-12 text-center text-s1-muted text-sm">
          Select an exception list to view items
        </div>

        <table v-else-if="items.length > 0" class="w-full">
          <thead class="border-b border-s1-border">
            <tr>
              <th class="table-header text-left">Name</th>
              <th class="table-header text-left">Entries</th>
              <th class="table-header text-left">Created</th>
              <th class="table-header w-10"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in items" :key="item.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ item.name }}</div>
                <div class="text-xs text-s1-muted">{{ item.description }}</div>
              </td>
              <td class="table-cell">
                <div v-for="(entry, i) in item.entries" :key="i" class="text-xs text-s1-subtle">
                  <span class="font-mono text-purple-400">{{ entry.field }}</span>
                  <span class="text-s1-muted mx-1">{{ entry.operator }}</span>
                  <span class="font-mono">{{ entry.value }}</span>
                </div>
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ item.created_at?.slice(0, 10) }}</td>
              <td class="table-cell" @click.stop>
                <button @click="deleteItem(item.id)" class="btn-ghost text-red-400 p-1">
                  <Trash2 class="w-3.5 h-3.5" />
                </button>
              </td>
            </tr>
          </tbody>
        </table>

        <EmptyState
          v-else-if="selectedListId && !loading"
          icon="--"
          title="No items"
          description="This exception list has no items yet."
        />
      </div>
    </div>
  </div>
</template>
