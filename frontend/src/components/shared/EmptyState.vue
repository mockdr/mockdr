<script setup lang="ts">
/** Centred empty-state placeholder with an emoji icon, title and description. */
withDefaults(defineProps<{
  icon?: string
  title?: string
  description?: string
}>(), {
  icon: '🔍',
  title: 'No results found',
  description: 'Try adjusting your filters.',
})
</script>

<template>
  <div class="flex flex-col items-center justify-center py-20 text-center">
    <div class="text-4xl mb-3">{{ icon }}</div>
    <h3 class="text-s1-text font-semibold mb-1">{{ title }}</h3>
    <p class="text-s1-muted text-sm">{{ description }}</p>
  </div>
</template>
