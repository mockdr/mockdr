<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { Shield, ArrowRight } from 'lucide-vue-next'
import { useAuthStore, PRESET_TOKENS } from '../stores/auth'

const router = useRouter()
const auth = useAuthStore()
const selectedToken = ref(PRESET_TOKENS[0].token)
const loading = ref(false)

async function login(): Promise<void> {
  loading.value = true
  try {
    await auth.login(selectedToken.value)
    router.push('/dashboard')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="min-h-screen bg-s1-bg flex items-center justify-center p-4">
    <div class="w-full max-w-sm">
      <!-- Logo -->
      <div class="flex items-center justify-center gap-3 mb-8">
        <div class="w-12 h-12 rounded-xl bg-s1-primary flex items-center justify-center">
          <Shield class="w-6 h-6 text-white" />
        </div>
        <div>
          <div class="text-s1-text text-xl font-bold">Mock S1</div>
          <div class="text-s1-muted text-sm">Hypervisor Platform</div>
        </div>
      </div>

      <!-- Card -->
      <div class="card p-6">
        <h1 class="text-lg font-semibold text-s1-text mb-1">Sign in</h1>
        <p class="text-s1-muted text-sm mb-6">Select a test API token to authenticate</p>

        <div class="space-y-3 mb-6">
          <button
            v-for="t in PRESET_TOKENS" :key="t.token"
            @click="selectedToken = t.token"
            class="w-full flex items-center gap-3 p-3 rounded-lg border transition-all"
            :class="selectedToken === t.token
              ? 'border-s1-primary bg-s1-primary/10'
              : 'border-s1-border hover:border-s1-primary/40 hover:bg-s1-hover'"
          >
            <div class="w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold"
              :class="selectedToken === t.token ? 'bg-s1-primary text-white' : 'bg-s1-border text-s1-muted'">
              {{ t.label[0] }}
            </div>
            <div class="text-left">
              <div class="text-sm font-medium text-s1-text">{{ t.label }}</div>
              <div class="text-xs text-s1-muted font-mono">{{ t.token.slice(0, 24) }}...</div>
            </div>
          </button>
        </div>

        <button
          @click="login"
          :disabled="loading"
          class="btn-primary w-full flex items-center justify-center gap-2"
        >
          <span>{{ loading ? 'Signing in...' : 'Sign In' }}</span>
          <ArrowRight v-if="!loading" class="w-4 h-4" />
        </button>
      </div>

      <p class="text-center text-xs text-s1-muted mt-4">
        Mock S1 · Development Environment
      </p>
    </div>
  </div>
</template>
