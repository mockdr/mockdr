import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

/**
 * Application router.
 *
 * All routes except /login are protected: the navigation guard redirects to
 * /login when no API token is present in localStorage.
 */
const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    component: () => import('../views/LoginView.vue'),
    meta: { public: true },
  },
  {
    path: '/',
    component: () => import('../components/layout/AppLayout.vue'),
    children: [
      { path: '',               redirect: '/dashboard' },
      { path: 'dashboard',      component: () => import('../views/DashboardView.vue') },
      { path: 'endpoints',      component: () => import('../views/EndpointsView.vue') },
      { path: 'endpoints/:id',  component: () => import('../views/EndpointDetailView.vue') },
      { path: 'threats',        component: () => import('../views/ThreatsView.vue') },
      { path: 'threats/:id',    component: () => import('../views/ThreatDetailView.vue') },
      { path: 'alerts',         component: () => import('../views/AlertsView.vue') },
      { path: 'deep-visibility',component: () => import('../views/DeepVisibilityView.vue') },
      { path: 'accounts',       component: () => import('../views/AccountsView.vue') },
      { path: 'sites',          component: () => import('../views/SitesView.vue') },
      { path: 'groups',         component: () => import('../views/GroupsView.vue') },
      { path: 'policies',       component: () => import('../views/PoliciesView.vue') },
      { path: 'exclusions',     component: () => import('../views/ExclusionsView.vue') },
      { path: 'blocklist',      component: () => import('../views/BlocklistView.vue') },
      { path: 'firewall-rules', component: () => import('../views/FirewallView.vue') },
      { path: 'device-control', component: () => import('../views/DeviceControlView.vue') },
      { path: 'tags',            component: () => import('../views/TagsView.vue') },
      { path: 'users',          component: () => import('../views/UsersView.vue') },
      { path: 'activities',     component: () => import('../views/ActivitiesView.vue') },
      { path: 'webhooks',       component: () => import('../views/WebhooksView.vue') },
      { path: 'request-audit',  component: () => import('../views/RequestAuditView.vue') },
      { path: 'export-import',  component: () => import('../views/ExportImportView.vue') },
      { path: 'rate-limit',     component: () => import('../views/RateLimitView.vue') },
      { path: 'recording-proxy', component: () => import('../views/RecordingProxyView.vue') },
      { path: 'playbooks', component: () => import('../views/PlaybookView.vue') },
      { path: 'ioc',       component: () => import('../views/IocView.vue') },
      // CrowdStrike
      { path: 'crowdstrike',               component: () => import('../views/cs/CsDashboardView.vue') },
      { path: 'crowdstrike/hosts',         component: () => import('../views/cs/CsHostsView.vue') },
      { path: 'crowdstrike/hosts/:id',     component: () => import('../views/cs/CsHostDetailView.vue') },
      { path: 'crowdstrike/detections',    component: () => import('../views/cs/CsDetectionsView.vue') },
      { path: 'crowdstrike/detections/:id', component: () => import('../views/cs/CsDetectionDetailView.vue') },
      { path: 'crowdstrike/incidents',     component: () => import('../views/cs/CsIncidentsView.vue') },
      { path: 'crowdstrike/cases',         component: () => import('../views/cs/CsCasesView.vue') },
      // Microsoft Defender
      { path: 'defender',                    component: () => import('../views/mde/MdeDashboardView.vue') },
      { path: 'defender/machines',           component: () => import('../views/mde/MdeMachinesView.vue') },
      { path: 'defender/machines/:id',       component: () => import('../views/mde/MdeMachineDetailView.vue') },
      { path: 'defender/alerts',             component: () => import('../views/mde/MdeAlertsView.vue') },
      { path: 'defender/indicators',         component: () => import('../views/mde/MdeIndicatorsView.vue') },
      { path: 'defender/vulnerabilities',    component: () => import('../views/mde/MdeVulnerabilitiesView.vue') },
      // Elastic Security
      { path: 'elastic',                     component: () => import('../views/elastic/EsDashboardView.vue') },
      { path: 'elastic/endpoints',           component: () => import('../views/elastic/EsEndpointsView.vue') },
      { path: 'elastic/rules',              component: () => import('../views/elastic/EsRulesView.vue') },
      { path: 'elastic/alerts',             component: () => import('../views/elastic/EsAlertsView.vue') },
      { path: 'elastic/cases',              component: () => import('../views/elastic/EsCasesView.vue') },
      { path: 'elastic/cases/:id',          component: () => import('../views/elastic/EsCaseDetailView.vue') },
      { path: 'elastic/exceptions',         component: () => import('../views/elastic/EsExceptionListsView.vue') },
      // Cortex XDR
      { path: 'cortex-xdr',                    component: () => import('../views/xdr/XdrDashboardView.vue') },
      { path: 'cortex-xdr/incidents',           component: () => import('../views/xdr/XdrIncidentsView.vue') },
      { path: 'cortex-xdr/incidents/:id',       component: () => import('../views/xdr/XdrIncidentDetailView.vue') },
      { path: 'cortex-xdr/alerts',              component: () => import('../views/xdr/XdrAlertsView.vue') },
      { path: 'cortex-xdr/endpoints',           component: () => import('../views/xdr/XdrEndpointsView.vue') },
      { path: 'cortex-xdr/endpoints/:id',       component: () => import('../views/xdr/XdrEndpointDetailView.vue') },
      { path: 'cortex-xdr/scripts',             component: () => import('../views/xdr/XdrScriptsView.vue') },
      { path: 'cortex-xdr/hash-exceptions',     component: () => import('../views/xdr/XdrHashExceptionsView.vue') },
      // Splunk SIEM
      { path: 'splunk',                          component: () => import('../views/splunk/SplunkDashboardView.vue') },
      { path: 'splunk/search',                   component: () => import('../views/splunk/SplunkSearchView.vue') },
      { path: 'splunk/notables',                 component: () => import('../views/splunk/SplunkNotablesView.vue') },
      { path: 'splunk/notables/:id',             component: () => import('../views/splunk/SplunkNotableDetailView.vue') },
      { path: 'splunk/indexes',                  component: () => import('../views/splunk/SplunkIndexesView.vue') },
      { path: 'splunk/hec',                      component: () => import('../views/splunk/SplunkHecView.vue') },
      // Microsoft Sentinel
      { path: 'sentinel',                         component: () => import('../views/sentinel/SentinelDashboardView.vue') },
      { path: 'sentinel/incidents',                component: () => import('../views/sentinel/SentinelIncidentsView.vue') },
      { path: 'sentinel/incidents/:id',            component: () => import('../views/sentinel/SentinelIncidentDetailView.vue') },
      { path: 'sentinel/watchlists',               component: () => import('../views/sentinel/SentinelWatchlistsView.vue') },
      { path: 'sentinel/threat-intelligence',      component: () => import('../views/sentinel/SentinelThreatIntelView.vue') },
      { path: 'sentinel/analytics',                component: () => import('../views/sentinel/SentinelAnalyticsView.vue') },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to) => {
  const token = localStorage.getItem('s1_token')
  if (!to.meta['public'] && !token) return '/login'
  // Hydrate the auth store if a token exists in localStorage but the store is empty
  if (token) {
    // Lazy import to avoid circular dependency — Pinia must be installed by the time this runs
    import('../stores/auth').then(({ useAuthStore }) => {
      const authStore = useAuthStore()
      if (!authStore.token) {
        authStore.login(token)
      }
    })
  }
})

export default router
