<script setup lang="ts">
/** Animated skeleton row placeholder for list loading states. */
withDefaults(defineProps<{ rows?: number }>(), { rows: 5 })
</script>

<template>
  <div class="animate-pulse">
    <div v-for="i in rows" :key="i" class="flex gap-4 py-3 px-4 border-b border-s1-border">
      <div class="w-4 h-4 bg-s1-border rounded"></div>
      <div class="flex-1 space-y-1.5">
        <div class="h-3 bg-s1-border rounded w-3/4"></div>
        <div class="h-3 bg-s1-border rounded w-1/2"></div>
      </div>
      <div class="h-3 bg-s1-border rounded w-20"></div>
      <div class="h-3 bg-s1-border rounded w-16"></div>
    </div>
  </div>
</template>
