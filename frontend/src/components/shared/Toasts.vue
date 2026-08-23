<script setup lang="ts">
import { X } from 'lucide-vue-next'
import { useNotificationsStore } from '../../stores/notifications'

const store = useNotificationsStore()
</script>

<template>
  <div
    class="fixed top-16 right-4 z-50 flex flex-col gap-2 w-80 max-w-[calc(100vw-2rem)]"
    role="status"
    aria-live="polite"
    aria-atomic="false"
  >
    <div
      v-for="n in store.notices"
      :key="n.id"
      :class="[
        'flex items-start gap-2 rounded-lg border px-3 py-2 text-sm shadow-lg',
        n.kind === 'error'
          ? 'bg-s1-card border-s1-danger/50 text-s1-text'
          : 'bg-s1-card border-s1-border text-s1-text',
      ]"
    >
      <span class="flex-1">{{ n.text }}</span>
      <button
        type="button"
        class="text-s1-muted hover:text-s1-text min-w-6 min-h-6 flex items-center justify-center"
        aria-label="Dismiss notification"
        @click="store.dismiss(n.id)"
      >
        <X class="w-4 h-4" />
      </button>
    </div>
  </div>
</template>
