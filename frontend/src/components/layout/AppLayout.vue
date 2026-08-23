<script setup lang="ts">
import Sidebar from './Sidebar.vue'
import Topbar from './Topbar.vue'
import DevMockPanel from '../DevMockPanel.vue'
import Toasts from '../shared/Toasts.vue'
</script>

<template>
  <div class="flex h-screen overflow-hidden bg-s1-bg">
    <a href="#main" class="skip-link">Skip to content</a>
    <Sidebar />
    <div class="flex-1 flex flex-col overflow-hidden">
      <Topbar />
      <main id="main" tabindex="-1" class="flex-1 overflow-y-auto p-6">
        <RouterView />
      </main>
    </div>
    <DevMockPanel />
    <Toasts />
  </div>
</template>
