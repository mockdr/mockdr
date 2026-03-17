<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { tagsApi } from '../api/tags'
import { sitesApi, groupsApi, accountsApi } from '../api/misc'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import { Plus, Trash2, Pencil, X } from 'lucide-vue-next'
import type { TagDefinition, Site, Group, Account } from '../types'

const items = ref<TagDefinition[]>([])
const total = ref(0)
const loading = ref(true)
const error = ref('')
const showAdd = ref(false)
const editingId = ref<string | null>(null)

// Form fields
const newKey = ref('')
const newValue = ref('')
const newDescription = ref('')
const newScopeLevel = ref<'global' | 'account' | 'site' | 'group'>('global')
const newScopeId = ref('')
const formError = ref('')

// Edit fields
const editKey = ref('')
const editValue = ref('')
const editDescription = ref('')

// Scope selector data
const sites = ref<Site[]>([])
const groups = ref<Group[]>([])
const accounts = ref<Account[]>([])

const scopeBadge = (level: string): string => {
  switch (level) {
    case 'global': return 'bg-purple-500/15 text-purple-400'
    case 'account': return 'bg-blue-500/15 text-blue-400'
    case 'site': return 'bg-green-500/15 text-green-400'
    case 'group': return 'bg-gray-500/15 text-gray-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

const scopeOptions = computed(() => {
  if (newScopeLevel.value === 'account') return accounts.value.map(a => ({ id: a.id, name: a.name }))
  if (newScopeLevel.value === 'site') return sites.value.map(s => ({ id: s.id, name: s.name }))
  if (newScopeLevel.value === 'group') return groups.value.map(g => ({ id: g.id, name: g.name }))
  return []
})

async function fetchList(): Promise<void> {
  loading.value = true
  try {
    const res = await tagsApi.list({ includeChildren: true, includeParents: true, limit: 200 })
    items.value = res.data
    total.value = res.pagination?.totalItems ?? res.data.length
  } finally {
    loading.value = false
  }
}

async function fetchScopeData(): Promise<void> {
  const [sitesRes, groupsRes, accountsRes] = await Promise.all([
    sitesApi.list({ limit: 100 }),
    groupsApi.list({ limit: 100 }),
    accountsApi.list({ limit: 100 }),
  ])
  sites.value = sitesRes.data?.sites ?? sitesRes.data ?? []
  groups.value = groupsRes.data ?? []
  accounts.value = accountsRes.data ?? []
}

async function addTag(): Promise<void> {
  if (!newKey.value.trim()) {
    formError.value = 'Tag key is required'
    return
  }
  formError.value = ''

  const filter: Record<string, unknown> = {}
  if (newScopeLevel.value === 'global') {
    filter.tenant = true
  } else if (newScopeLevel.value === 'account' && newScopeId.value) {
    filter.accountIds = [newScopeId.value]
  } else if (newScopeLevel.value === 'site' && newScopeId.value) {
    filter.siteIds = [newScopeId.value]
  } else if (newScopeLevel.value === 'group' && newScopeId.value) {
    filter.groupIds = [newScopeId.value]
  } else {
    filter.tenant = true
  }

  error.value = ''
  try {
    await tagsApi.create({
      data: {
        key: newKey.value,
        value: newValue.value || newKey.value,
        type: 'agents',
        description: newDescription.value,
      },
      filter,
    })
    newKey.value = ''
    newValue.value = ''
    newDescription.value = ''
    newScopeLevel.value = 'global'
    newScopeId.value = ''
    showAdd.value = false
    await fetchList()
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to create tag'
  }
}

function startEdit(tag: TagDefinition): void {
  editingId.value = tag.id
  editKey.value = tag.key
  editValue.value = tag.value
  editDescription.value = tag.description ?? ''
}

async function saveEdit(id: string): Promise<void> {
  await tagsApi.update(id, {
    data: {
      key: editKey.value,
      value: editValue.value,
      description: editDescription.value,
    },
  })
  editingId.value = null
  await fetchList()
}

async function removeTag(id: string): Promise<void> {
  if (!confirm('Are you sure you want to delete this tag?')) return
  error.value = ''
  try {
    await tagsApi.delete(id)
    items.value = items.value.filter(t => t.id !== id)
    total.value--
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to delete tag'
  }
}

onMounted(async () => {
  await Promise.all([fetchList(), fetchScopeData()])
})
</script>

<template>
  <div class="space-y-4">
    <div v-if="error" class="error-banner">{{ error }}</div>
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Endpoint Tags</h1>
        <p class="text-s1-muted text-sm">{{ total }} tag definitions</p>
      </div>
      <button @click="showAdd = !showAdd" class="btn-primary flex items-center gap-2 text-sm">
        <Plus class="w-4 h-4" /> Create Tag
      </button>
    </div>

    <!-- Add form -->
    <div v-if="showAdd" class="card p-4 space-y-3">
      <div class="grid grid-cols-4 gap-3">
        <div>
          <label for="tag-key" class="text-xs text-s1-muted mb-1 block">Key <span class="text-s1-danger">*</span></label>
          <input id="tag-key" v-model="newKey" class="input w-full" placeholder="e.g. Virtual" />
        </div>
        <div>
          <label for="tag-value" class="text-xs text-s1-muted mb-1 block">Value</label>
          <input id="tag-value" v-model="newValue" class="input w-full" placeholder="e.g. Virtual" />
        </div>
        <div>
          <label for="tag-scope" class="text-xs text-s1-muted mb-1 block">Scope</label>
          <select id="tag-scope" v-model="newScopeLevel" class="input w-full text-sm" @change="newScopeId = ''">
            <option value="global">Global</option>
            <option value="account">Account</option>
            <option value="site">Site</option>
            <option value="group">Group</option>
          </select>
        </div>
        <div v-if="newScopeLevel !== 'global'">
          <label for="tag-scope-id" class="text-xs text-s1-muted mb-1 block">{{ newScopeLevel }}</label>
          <select id="tag-scope-id" v-model="newScopeId" class="input w-full text-sm">
            <option value="" disabled>Select...</option>
            <option v-for="opt in scopeOptions" :key="opt.id" :value="opt.id">{{ opt.name }}</option>
          </select>
        </div>
        <div class="col-span-3">
          <label for="tag-description" class="text-xs text-s1-muted mb-1 block">Description</label>
          <input id="tag-description" v-model="newDescription" class="input w-full" placeholder="Optional description" />
        </div>
        <div class="flex flex-col items-end gap-2">
          <p v-if="formError" class="text-xs text-s1-danger w-full" role="alert">{{ formError }}</p>
          <div class="flex gap-2 w-full">
            <button @click="addTag" class="btn-primary text-sm w-full">Create</button>
            <button @click="showAdd = false" class="btn-ghost text-sm w-full">Cancel</button>
          </div>
        </div>
      </div>
    </div>

    <div class="card overflow-hidden">
      <div v-if="loading"><LoadingSkeleton :rows="6" /></div>
      <EmptyState v-else-if="!items.length" title="No tags" description="No tag definitions found" />
      <table v-else class="w-full text-sm">
        <thead class="border-b border-s1-border">
          <tr class="text-left text-xs text-s1-muted uppercase tracking-wide">
            <th class="px-5 py-3">Key</th>
            <th class="px-5 py-3">Value</th>
            <th class="px-5 py-3">Scope</th>
            <th class="px-5 py-3">Scope Path</th>
            <th class="px-5 py-3">Endpoints</th>
            <th class="px-5 py-3">Description</th>
            <th class="px-5 py-3">Created</th>
            <th class="px-5 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="tag in items" :key="tag.id"
            class="border-b border-s1-border/50 hover:bg-s1-hover transition-colors"
          >
            <!-- Inline edit mode -->
            <template v-if="editingId === tag.id">
              <td class="px-5 py-2">
                <input v-model="editKey" class="input w-full text-xs" />
              </td>
              <td class="px-5 py-2">
                <input v-model="editValue" class="input w-full text-xs" />
              </td>
              <td class="px-5 py-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-medium" :class="scopeBadge(tag.scopeLevel)">
                  {{ tag.scopeLevel }}
                </span>
              </td>
              <td class="px-5 py-3 text-s1-muted text-xs">{{ tag.scopePath }}</td>
              <td class="px-5 py-3 text-s1-muted text-xs">{{ tag.totalEndpoints }}</td>
              <td class="px-5 py-2">
                <input v-model="editDescription" class="input w-full text-xs" />
              </td>
              <td class="px-5 py-3 text-s1-muted text-xs">{{ tag.createdAt?.slice(0, 10) }}</td>
              <td class="px-5 py-3 flex gap-1">
                <button @click="saveEdit(tag.id)" class="text-s1-primary hover:text-s1-primary/80 text-xs font-medium">Save</button>
                <button @click="editingId = null" aria-label="Cancel edit" class="text-s1-muted hover:text-s1-text">
                  <X class="w-4 h-4" />
                </button>
              </td>
            </template>

            <!-- Normal display -->
            <template v-else>
              <td class="px-5 py-3 font-medium text-s1-text">{{ tag.key }}</td>
              <td class="px-5 py-3 text-s1-muted">{{ tag.value }}</td>
              <td class="px-5 py-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-medium" :class="scopeBadge(tag.scopeLevel)">
                  {{ tag.scopeLevel }}
                </span>
              </td>
              <td class="px-5 py-3 text-s1-muted text-xs font-mono">{{ tag.scopePath }}</td>
              <td class="px-5 py-3 text-s1-muted text-xs">
                <span :title="`${tag.endpointsInCurrentScope} in scope / ${tag.totalEndpoints} total`">
                  {{ tag.totalEndpoints }}
                </span>
              </td>
              <td class="px-5 py-3 text-s1-muted text-xs max-w-xs truncate">{{ tag.description }}</td>
              <td class="px-5 py-3 text-s1-muted text-xs">{{ tag.createdAt?.slice(0, 10) }}</td>
              <td class="px-5 py-3 flex gap-2">
                <button @click="startEdit(tag)" aria-label="Edit tag" class="text-s1-muted hover:text-s1-primary transition-colors">
                  <Pencil class="w-4 h-4" />
                </button>
                <button @click="removeTag(tag.id)" aria-label="Delete tag" class="text-s1-muted hover:text-s1-danger transition-colors">
                  <Trash2 class="w-4 h-4" />
                </button>
              </td>
            </template>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
