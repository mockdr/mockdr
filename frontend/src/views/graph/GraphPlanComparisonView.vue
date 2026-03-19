<script setup lang="ts">
import { ref } from 'vue'

interface PlanFeature {
  name: string
  plan1: boolean
  plan2: boolean
  defenderBusiness: boolean
}

const features = ref<PlanFeature[]>([
  { name: 'Endpoint Detection & Response (EDR)', plan1: false, plan2: true, defenderBusiness: true },
  { name: 'Advanced Hunting', plan1: false, plan2: true, defenderBusiness: false },
  { name: 'Automated Investigation & Response', plan1: false, plan2: true, defenderBusiness: true },
  { name: 'Threat & Vulnerability Management', plan1: true, plan2: true, defenderBusiness: true },
  { name: 'Attack Surface Reduction', plan1: true, plan2: true, defenderBusiness: true },
  { name: 'Next-Gen Antivirus', plan1: true, plan2: true, defenderBusiness: true },
  { name: 'Identity Protection (Entra ID P2)', plan1: false, plan2: true, defenderBusiness: false },
  { name: 'Intune Device Management', plan1: false, plan2: true, defenderBusiness: true },
  { name: 'Conditional Access', plan1: false, plan2: true, defenderBusiness: true },
  { name: 'Microsoft Secure Score', plan1: true, plan2: true, defenderBusiness: true },
  { name: 'Threat Analytics', plan1: false, plan2: true, defenderBusiness: false },
  { name: 'Endpoint Firewall Management', plan1: true, plan2: true, defenderBusiness: true },
  { name: 'Device Control', plan1: true, plan2: true, defenderBusiness: false },
  { name: 'Web Content Filtering', plan1: true, plan2: true, defenderBusiness: true },
  { name: 'Centralized Management (M365 Defender)', plan1: true, plan2: true, defenderBusiness: true },
])

const currentPlan = ref('plan2')
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Plan Comparison
        </h1>
        <p class="text-s1-muted text-sm">Microsoft 365 Defender plan feature comparison</p>
      </div>
      <div class="flex items-center gap-2">
        <span class="text-xs text-s1-muted">Current plan:</span>
        <select v-model="currentPlan" class="select">
          <option value="plan1">Plan 1</option>
          <option value="plan2">Plan 2</option>
          <option value="defenderBusiness">Defender for Business</option>
        </select>
      </div>
    </div>

    <!-- Comparison table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Feature</th>
            <th
              class="table-header text-center"
              :class="currentPlan === 'plan1' ? 'bg-blue-500/10' : ''"
            >
              Plan 1
            </th>
            <th
              class="table-header text-center"
              :class="currentPlan === 'plan2' ? 'bg-blue-500/10' : ''"
            >
              Plan 2
            </th>
            <th
              class="table-header text-center"
              :class="currentPlan === 'defenderBusiness' ? 'bg-blue-500/10' : ''"
            >
              Defender for Business
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="feature in features" :key="feature.name" class="table-row">
            <td class="table-cell text-sm text-s1-text">{{ feature.name }}</td>
            <td
              class="table-cell text-center"
              :class="currentPlan === 'plan1' ? 'bg-blue-500/5' : ''"
            >
              <span v-if="feature.plan1" class="text-green-400 text-base font-bold">&#10003;</span>
              <span v-else class="text-red-400 text-base font-bold">&#10007;</span>
            </td>
            <td
              class="table-cell text-center"
              :class="currentPlan === 'plan2' ? 'bg-blue-500/5' : ''"
            >
              <span v-if="feature.plan2" class="text-green-400 text-base font-bold">&#10003;</span>
              <span v-else class="text-red-400 text-base font-bold">&#10007;</span>
            </td>
            <td
              class="table-cell text-center"
              :class="currentPlan === 'defenderBusiness' ? 'bg-blue-500/5' : ''"
            >
              <span v-if="feature.defenderBusiness" class="text-green-400 text-base font-bold">&#10003;</span>
              <span v-else class="text-red-400 text-base font-bold">&#10007;</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
