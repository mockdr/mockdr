<script setup lang="ts">
import { ref } from 'vue'
import { Download, Upload, CheckCircle, AlertCircle } from 'lucide-vue-next'
import { systemApi } from '../api/system'

const exporting = ref(false)
const importing = ref(false)
const importStatus = ref<'idle' | 'success' | 'error'>('idle')
const importMessage = ref('')
const fileInput = ref<HTMLInputElement | null>(null)

async function doExport(): Promise<void> {
  exporting.value = true
  try {
    const res = await systemApi.exportState()
    const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `mockdr-snapshot-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.json`
    a.click()
    URL.revokeObjectURL(url)
  } finally {
    exporting.value = false
  }
}

function triggerImport(): void {
  fileInput.value?.click()
}

async function onFileSelected(event: Event): Promise<void> {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  input.value = ''
  importing.value = true
  importStatus.value = 'idle'
  importMessage.value = ''
  try {
    const text = await file.text()
    const snapshot = JSON.parse(text)
    await systemApi.importState(snapshot)
    importStatus.value = 'success'
    importMessage.value = `Snapshot "${file.name}" imported successfully.`
  } catch (e: unknown) {
    importStatus.value = 'error'
    importMessage.value = e instanceof Error ? e.message : 'Import failed — invalid snapshot format'
  } finally {
    importing.value = false
  }
}
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-xl font-bold text-s1-text">Export / Import</h1>
      <p class="text-s1-muted text-sm">Save and restore the full in-memory store state as a JSON snapshot</p>
    </div>

    <div class="grid md:grid-cols-2 gap-6">
      <!-- Export -->
      <div class="card p-6 space-y-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-s1-primary/15 flex items-center justify-center">
            <Download class="w-5 h-5 text-s1-primary" />
          </div>
          <div>
            <h2 class="text-s1-text font-semibold">Export Snapshot</h2>
            <p class="text-s1-muted text-xs">Download current state as JSON</p>
          </div>
        </div>

        <p class="text-s1-subtle text-sm">
          Exports all collections — agents, threats, sites, groups, users, exclusions, webhooks, and more —
          into a single JSON file you can import later or share with teammates.
        </p>

        <button
          @click="doExport"
          :disabled="exporting"
          class="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-sm font-medium text-white bg-s1-primary hover:bg-s1-primary-dark transition-colors disabled:opacity-50"
        >
          <Download class="w-4 h-4" :class="exporting ? 'animate-bounce' : ''" />
          {{ exporting ? 'Exporting…' : 'Download Snapshot' }}
        </button>
      </div>

      <!-- Import -->
      <div class="card p-6 space-y-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-s1-cyan/15 flex items-center justify-center">
            <Upload class="w-5 h-5 text-s1-cyan" />
          </div>
          <div>
            <h2 class="text-s1-text font-semibold">Import Snapshot</h2>
            <p class="text-s1-muted text-xs">Restore state from a JSON file</p>
          </div>
        </div>

        <p class="text-s1-subtle text-sm">
          Upload a previously exported snapshot to replace the current in-memory state.
          The server resets and reloads from the file — useful for reproducing specific scenarios.
        </p>

        <input ref="fileInput" type="file" accept="application/json,.json" class="hidden" @change="onFileSelected" />

        <button
          @click="triggerImport"
          :disabled="importing"
          class="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-sm font-medium text-s1-cyan bg-s1-cyan/10 hover:bg-s1-cyan/20 transition-colors disabled:opacity-50"
        >
          <Upload class="w-4 h-4" :class="importing ? 'animate-bounce' : ''" />
          {{ importing ? 'Importing…' : 'Upload Snapshot' }}
        </button>

        <!-- Status -->
        <Transition name="fade">
          <div
            v-if="importStatus !== 'idle'"
            class="flex items-start gap-2 p-3 rounded-lg text-sm"
            :class="importStatus === 'success' ? 'bg-s1-success/10 text-s1-success' : 'bg-s1-danger/10 text-s1-danger'"
          >
            <CheckCircle v-if="importStatus === 'success'" class="w-4 h-4 flex-shrink-0 mt-0.5" />
            <AlertCircle v-else class="w-4 h-4 flex-shrink-0 mt-0.5" />
            <span>{{ importMessage }}</span>
          </div>
        </Transition>
      </div>
    </div>

    <!-- Info box -->
    <div class="card p-5 border-s1-primary/20 bg-s1-primary/5">
      <div class="text-xs font-semibold text-s1-primary uppercase tracking-wide mb-2">How it works</div>
      <ul class="text-s1-subtle text-sm space-y-1 list-disc list-inside">
        <li>Export serialises the entire in-memory store — no external dependencies required</li>
        <li>Snapshots capture all typed domain objects (agents, threats, sites, groups, users…) and raw records</li>
        <li>Importing replaces state atomically — the page will reflect new data on next reload</li>
        <li>Use snapshots as reproducible test fixtures or shared demo states</li>
      </ul>
    </div>
  </div>
</template>

<style scoped>
.fade-enter-active, .fade-leave-active { transition: opacity 0.2s; }
.fade-enter-from, .fade-leave-to { opacity: 0; }
</style>
