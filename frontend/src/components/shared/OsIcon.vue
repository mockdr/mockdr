<script setup lang="ts">
/** Displays an emoji representing the agent's operating system. */
const props = defineProps<{ osType: string }>()
const icons: Record<string, string> = { windows: '🪟', macos: '🍎', linux: '🐧' }
</script>

<template>
  <span :title="props.osType" class="select-none text-base">{{ icons[props.osType] ?? '💻' }}</span>
</template>
