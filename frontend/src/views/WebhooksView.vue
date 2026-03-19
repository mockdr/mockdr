<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Plus, Trash2, Zap, RefreshCw, X } from 'lucide-vue-next'
import { webhooksApi } from '../api/system'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import type { WebhookSubscription } from '../types'

const hooks = ref<WebhookSubscription[]>([])
const loading = ref(true)
const firing = ref<string | null>(null)
const error = ref('')
const showCreate = ref(false)

const ALL_EVENTS = [
  'threat.created', 'threat.updated', 'alert.created', 'agent.offline', 'agent.infected',
]

const form = ref({
  url: '',
  description: '',
  secret: '',
  event_types: [] as string[],
})
const creating = ref(false)
const createError = ref('')

async function fetchHooks(): Promise<void> {
  loading.value = true
  try {
    const res = await webhooksApi.list()
    hooks.value = res.data
  } finally {
    loading.value = false
  }
}

async function createHook(): Promise<void> {
  createError.value = ''
  if (!form.value.url) { createError.value = 'URL is required'; return }
  if (!form.value.event_types.length) { createError.value = 'Select at least one event type'; return }
  creating.value = true
  try {
    const res = await webhooksApi.create(form.value)
    hooks.value.push(res.data)
    showCreate.value = false
    form.value = { url: '', description: '', secret: '', event_types: [] }
  } catch (e: unknown) {
    createError.value = e instanceof Error ? e.message : 'Failed to create webhook'
  } finally {
    creating.value = false
  }
}

async function deleteHook(id: string): Promise<void> {
  try {
    await webhooksApi.delete(id)
    hooks.value = hooks.value.filter((h) => h.id !== id)
    error.value = ''
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to delete webhook'
  }
}

async function fireEvent(eventType: string): Promise<void> {
  firing.value = eventType
  try {
    await webhooksApi.fire(eventType)
  } finally {
    firing.value = null
  }
}

function toggleEventType(et: string): void {
  const idx = form.value.event_types.indexOf(et)
  if (idx === -1) form.value.event_types.push(et)
  else form.value.event_types.splice(idx, 1)
}

onMounted(() => fetchHooks())
</script>

<template>
  <div class="space-y-4">
    <div v-if="error" class="error-banner">{{ error }}</div>
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Webhook Subscriptions</h1>
        <p class="text-s1-muted text-sm">{{ hooks.length }} registered endpoint{{ hooks.length !== 1 ? 's' : '' }}</p>
      </div>
      <div class="flex items-center gap-2">
        <button @click="fetchHooks" :disabled="loading" class="btn-ghost flex items-center gap-1.5 text-sm">
          <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
          Refresh
        </button>
        <button @click="showCreate = true" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm text-white bg-s1-primary hover:bg-s1-primary-dark transition-colors">
          <Plus class="w-3.5 h-3.5" />
          Add Webhook
        </button>
      </div>
    </div>

    <!-- Fire a test event -->
    <div class="card p-4">
      <div class="text-xs font-semibold text-s1-muted uppercase tracking-wide mb-3">Fire Test Event</div>
      <div class="flex flex-wrap gap-2">
        <button
          v-for="et in ALL_EVENTS" :key="et"
          @click="fireEvent(et)"
          :disabled="firing !== null"
          class="px-3 py-1.5 rounded-lg text-xs font-medium bg-s1-hover hover:bg-s1-primary/20 hover:text-s1-primary text-s1-subtle transition-colors disabled:opacity-50 flex items-center gap-1.5"
        >
          <Zap class="w-3 h-3" :class="firing === et ? 'animate-pulse text-s1-warning' : ''" />
          {{ et }}
        </button>
      </div>
    </div>

    <!-- Webhook list -->
    <div class="card overflow-hidden">
      <div v-if="loading && !hooks.length"><LoadingSkeleton :rows="4" /></div>
      <EmptyState v-else-if="!hooks.length" title="No webhooks" description="Add a webhook endpoint to receive real-time events" />

      <div v-else class="divide-y divide-s1-border/50">
        <div v-for="hook in hooks" :key="hook.id" class="px-5 py-4 flex items-start gap-4">
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-1">
              <span class="w-2 h-2 rounded-full flex-shrink-0" :class="hook.active ? 'bg-s1-success' : 'bg-s1-muted'" />
              <span class="text-s1-text text-sm font-medium truncate">{{ hook.url }}</span>
            </div>
            <div v-if="hook.description" class="text-xs text-s1-muted mb-1">{{ hook.description }}</div>
            <div class="flex flex-wrap gap-1 mt-1">
              <span
                v-for="et in hook.event_types" :key="et"
                class="px-1.5 py-0.5 bg-s1-primary/10 text-s1-primary text-[10px] rounded font-mono"
              >{{ et }}</span>
            </div>
            <div class="text-[11px] text-s1-muted mt-1">Created {{ hook.created_at.slice(0, 10) }}</div>
          </div>
          <button @click="deleteHook(hook.id)" class="flex-shrink-0 text-s1-muted hover:text-s1-danger transition-colors">
            <Trash2 class="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>

    <!-- Create modal -->
    <Teleport to="body">
      <Transition name="modal">
        <div v-if="showCreate" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" @click.self="showCreate = false">
          <div class="card w-full max-w-md mx-4 p-6 space-y-4">
            <div class="flex items-center justify-between">
              <h2 class="text-s1-text font-semibold">New Webhook</h2>
              <button @click="showCreate = false" class="text-s1-muted hover:text-s1-text transition-colors">
                <X class="w-4 h-4" />
              </button>
            </div>

            <div class="space-y-3">
              <div>
                <label class="text-xs text-s1-muted uppercase tracking-wide">Endpoint URL *</label>
                <input v-model="form.url" type="url" placeholder="https://your-server.example.com/hook"
                  class="mt-1 w-full px-3 py-2 bg-s1-bg border border-s1-border rounded-lg text-s1-text text-sm focus:outline-none focus:border-s1-primary/60" />
              </div>
              <div>
                <label class="text-xs text-s1-muted uppercase tracking-wide">Description</label>
                <input v-model="form.description" type="text" placeholder="Optional label"
                  class="mt-1 w-full px-3 py-2 bg-s1-bg border border-s1-border rounded-lg text-s1-text text-sm focus:outline-none focus:border-s1-primary/60" />
              </div>
              <div>
                <label class="text-xs text-s1-muted uppercase tracking-wide">Signing Secret (HMAC-SHA256)</label>
                <input v-model="form.secret" type="text" placeholder="Leave blank to auto-generate"
                  class="mt-1 w-full px-3 py-2 bg-s1-bg border border-s1-border rounded-lg text-s1-text text-sm font-mono focus:outline-none focus:border-s1-primary/60" />
              </div>
              <div>
                <label class="text-xs text-s1-muted uppercase tracking-wide">Event Types *</label>
                <div class="mt-2 flex flex-wrap gap-2">
                  <button
                    v-for="et in ALL_EVENTS" :key="et"
                    @click="toggleEventType(et)"
                    class="px-2.5 py-1 rounded text-xs font-mono transition-colors"
                    :class="form.event_types.includes(et)
                      ? 'bg-s1-primary text-white'
                      : 'bg-s1-bg border border-s1-border text-s1-subtle hover:border-s1-primary/50'"
                  >{{ et }}</button>
                </div>
              </div>
            </div>

            <div v-if="createError" class="text-s1-danger text-xs">{{ createError }}</div>

            <div class="flex gap-2 justify-end pt-1">
              <button @click="showCreate = false" class="btn-ghost text-sm px-4 py-2">Cancel</button>
              <button @click="createHook" :disabled="creating" class="px-4 py-2 rounded-lg text-sm text-white bg-s1-primary hover:bg-s1-primary-dark transition-colors disabled:opacity-50">
                {{ creating ? 'Creating…' : 'Create' }}
              </button>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<style scoped>
.modal-enter-active, .modal-leave-active { transition: opacity 0.15s; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
</style>
