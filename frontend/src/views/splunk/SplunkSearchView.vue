<script setup lang="ts">
import { ref } from 'vue'
import { Search, Play, Loader2 } from 'lucide-vue-next'
import { splunkSearchApi } from '../../api/splunk'

const query = ref('search index=sentinelone sourcetype=sentinelone:channel:threats | head 20')
const results = ref<Record<string, unknown>[]>([])
const fields = ref<string[]>([])
const loading = ref(false)
const error = ref('')
const resultCount = ref(0)

async function runSearch(): Promise<void> {
  if (!query.value.trim()) return
  loading.value = true
  error.value = ''
  results.value = []
  fields.value = []
  try {
    const { sid } = await splunkSearchApi.createJob(query.value)
    // Poll until job is done before fetching results
    let isDone = false
    while (!isDone) {
      const jobStatus = await splunkSearchApi.getJob(sid)
      const entry = Array.isArray(jobStatus.entry) ? jobStatus.entry[0] : null
      isDone = entry?.content?.isDone ?? false
      if (!isDone) await new Promise(r => setTimeout(r, 500))
    }
    const res = await splunkSearchApi.getResults(sid, 100)
    results.value = res.results ?? []
    fields.value = (res.fields ?? []).map(f => f.name)
    resultCount.value = results.value.length
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Search failed'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
        <Search class="w-5 h-5 text-green-500" />
        Splunk Search
      </h1>
      <p class="text-s1-muted text-sm">Run SPL queries against the mock Splunk event store</p>
    </div>

    <!-- Search bar -->
    <div class="card p-4">
      <div class="flex gap-3">
        <input
          v-model="query"
          type="text"
          class="flex-1 bg-s1-input border border-s1-border rounded-lg px-4 py-2.5 text-sm text-s1-text font-mono
                 focus:outline-none focus:ring-2 focus:ring-green-500/40 focus:border-green-500/40"
          placeholder="search index=... sourcetype=..."
          @keyup.enter="runSearch"
        />
        <button
          @click="runSearch"
          :disabled="loading"
          class="px-5 py-2.5 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm font-medium
                 flex items-center gap-2 transition-colors disabled:opacity-50"
        >
          <Loader2 v-if="loading" class="w-4 h-4 animate-spin" />
          <Play v-else class="w-4 h-4" />
          Search
        </button>
      </div>
    </div>

    <!-- Error -->
    <div v-if="error" class="card p-4 border-red-500/40 bg-red-500/10 text-red-400 text-sm">
      {{ error }}
    </div>

    <!-- Results -->
    <div v-if="results.length" class="card">
      <div class="px-5 py-3 border-b border-s1-border">
        <span class="text-sm text-s1-muted">{{ resultCount }} results</span>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-s1-border">
              <th
                v-for="f in fields.slice(0, 8)" :key="f"
                class="px-4 py-2 text-left text-xs font-medium text-s1-muted uppercase tracking-wider"
              >
                {{ f }}
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-s1-border">
            <tr v-for="(row, i) in results" :key="i" class="hover:bg-s1-hover">
              <td
                v-for="f in fields.slice(0, 8)" :key="f"
                class="px-4 py-2 text-s1-text truncate max-w-[200px]"
              >
                {{ row[f] ?? '' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div v-if="!loading && !results.length && !error" class="card p-12 text-center text-s1-muted text-sm">
      Enter an SPL query and click Search to see results
    </div>
  </div>
</template>
