<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, Send } from 'lucide-vue-next'
import { esCasesApi } from '../../api/elastic'
import type { EsCase, EsCaseComment } from '../../types/elastic'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const route = useRoute()
const router = useRouter()
const id = route.params['id'] as string

const caseData = ref<EsCase | null>(null)
const comments = ref<EsCaseComment[]>([])
const loading = ref(true)
const commentText = ref('')
const submitting = ref(false)
const error = ref('')

function severityBadgeClass(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500/15 text-red-400'
    case 'high': return 'bg-orange-500/15 text-orange-400'
    case 'medium': return 'bg-yellow-500/15 text-yellow-400'
    case 'low': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'open': return 'bg-blue-500/15 text-blue-400'
    case 'in-progress': return 'bg-yellow-500/15 text-yellow-400'
    case 'closed': return 'bg-green-500/15 text-green-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function formatTime(ts: string): string {
  if (!ts) return '--'
  return new Date(ts).toLocaleString()
}

async function addComment(): Promise<void> {
  if (!commentText.value.trim()) return
  submitting.value = true
  try {
    await esCasesApi.addComment(id, {
      comment: commentText.value,
      type: 'user',
    })
    commentText.value = ''
    // Refresh comments
    const commentsRes = await esCasesApi.getComments(id)
    comments.value = commentsRes.data ?? []
  } finally {
    submitting.value = false
  }
}

async function updateStatus(newStatus: string): Promise<void> {
  if (!caseData.value) return
  try {
    await esCasesApi.update({
      cases: [{ id, version: caseData.value.updated_at, status: newStatus }],
    })
    caseData.value.status = newStatus
    error.value = ''
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to update case status'
  }
}

onMounted(async () => {
  try {
    const [caseRes, commentsRes] = await Promise.all([
      esCasesApi.get(id),
      esCasesApi.getComments(id),
    ])
    caseData.value = caseRes
    comments.value = commentsRes.data ?? []
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <div v-if="error" class="error-banner">{{ error }}</div>
    <!-- Back -->
    <button @click="router.push('/elastic/cases')" class="btn-ghost flex items-center gap-2 mb-4 -ml-2">
      <ArrowLeft class="w-4 h-4" /> ES Cases
    </button>

    <div v-if="loading" class="card p-6"><LoadingSkeleton :rows="8" /></div>

    <div v-else-if="caseData" class="grid grid-cols-3 gap-4">
      <!-- Left: Case info -->
      <div class="card p-5 space-y-4">
        <div>
          <h2 class="text-lg font-bold text-s1-text">{{ caseData.title }}</h2>
          <div class="flex items-center gap-2 mt-2">
            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
              :class="statusBadgeClass(caseData.status)">
              {{ caseData.status }}
            </span>
            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
              :class="severityBadgeClass(caseData.severity)">
              {{ caseData.severity }}
            </span>
          </div>
        </div>

        <div v-if="caseData.description" class="text-sm text-s1-subtle">
          {{ caseData.description }}
        </div>

        <!-- Status actions -->
        <div class="space-y-2">
          <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider">Actions</div>
          <div class="flex flex-wrap gap-2">
            <button v-if="caseData.status !== 'in-progress'" @click="updateStatus('in-progress')"
              class="btn-ghost text-xs text-yellow-400">Mark In Progress</button>
            <button v-if="caseData.status !== 'closed'" @click="updateStatus('closed')"
              class="btn-ghost text-xs text-green-400">Close</button>
            <button v-if="caseData.status === 'closed'" @click="updateStatus('open')"
              class="btn-ghost text-xs text-blue-400">Reopen</button>
          </div>
        </div>

        <div class="space-y-2 text-sm">
          <div v-for="[k, v] in [
            ['Case ID', caseData.id],
            ['Created by', caseData.created_by?.username],
            ['Created', formatTime(caseData.created_at)],
            ['Updated', formatTime(caseData.updated_at)],
            ['Comments', caseData.total_comment],
          ]" :key="(k as string)" class="flex justify-between gap-2">
            <span class="text-s1-muted">{{ k }}</span>
            <span class="text-s1-text text-right truncate max-w-[60%] font-mono text-xs">{{ v ?? '--' }}</span>
          </div>

          <div v-if="caseData.tags?.length" class="pt-2">
            <div class="text-s1-muted text-xs mb-1.5">Tags</div>
            <div class="flex flex-wrap gap-1">
              <span v-for="tag in caseData.tags" :key="tag"
                class="text-xs px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-400 font-medium">
                {{ tag }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Right: Comments timeline -->
      <div class="col-span-2 card overflow-hidden">
        <div class="px-5 py-4 border-b border-s1-border">
          <h3 class="text-sm font-semibold text-s1-text">Comments ({{ comments.length }})</h3>
        </div>

        <div class="p-5 space-y-4 overflow-y-auto max-h-[50vh]">
          <div v-if="!comments.length" class="py-8 text-center text-s1-muted text-sm">
            No comments yet
          </div>
          <div
            v-for="comment in comments" :key="comment.id"
            class="rounded-lg border border-s1-border p-4"
          >
            <div class="flex items-center justify-between mb-2">
              <span class="text-sm font-medium text-s1-text">
                {{ comment.created_by?.username ?? 'Unknown' }}
              </span>
              <span class="text-xs text-s1-muted">{{ formatTime(comment.created_at) }}</span>
            </div>
            <div class="text-sm text-s1-subtle whitespace-pre-wrap">{{ comment.comment }}</div>
          </div>
        </div>

        <!-- Add comment -->
        <div class="p-4 border-t border-s1-border">
          <div class="flex items-end gap-2">
            <textarea
              v-model="commentText"
              class="input flex-1 resize-none"
              rows="2"
              placeholder="Add a comment..."
            ></textarea>
            <button
              @click="addComment()"
              :disabled="!commentText.trim() || submitting"
              class="btn-ghost flex items-center gap-1.5 text-purple-400"
            >
              <Send class="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="card p-10 text-center">
      <p class="text-s1-muted">Case not found</p>
      <button @click="router.push('/elastic/cases')" class="btn-ghost mt-4 text-sm">Back to cases</button>
    </div>
  </div>
</template>
