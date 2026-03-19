<script setup lang="ts">
import Sidebar from './Sidebar.vue'
import Topbar from './Topbar.vue'
import DevMockPanel from '../DevMockPanel.vue'
</script>

<template>
  <div class="flex h-screen overflow-hidden bg-s1-bg">
    <Sidebar />
    <div class="flex-1 flex flex-col overflow-hidden">
      <Topbar />
      <main class="flex-1 overflow-y-auto p-6">
        <RouterView />
      </main>
    </div>
    <DevMockPanel />
  </div>
</template>
