// apps/web/src/stores/detection.ts
//
// Pinia store for the Detection Center (检测中心) page. The store
// extends the previous read-only fetches with the tool-call surface:
//   - toggleEngine(id, enabled)  — PATCH /engines/:id
//   - runHealthCheck(id)         — POST  /engines/:id/health-check
//   - syncRules(id)              — POST  /engines/:id/sync
//   - triggerScan({projectId})   — POST  /scans/trigger
//
// Every mutator optimistically updates the relevant list and reloads
// the rest so the four cards on the Engines / Queue tabs stay in
// sync without a full-page refresh.
import { defineStore } from 'pinia';
import { ref } from 'vue';
import * as api from '@/api/detection';

export type Engine = api.Engine;
export type Rule = api.Rule;
export type Policy = api.PolicyConfig;
export type QueueItem = api.QueueItem;

export const useDetectionStore = defineStore('detection', () => {
  const engines = ref<Engine[]>([]);
  const rules = ref<Rule[]>([]);
  const policies = ref<Policy[]>([]);
  const queue = ref<QueueItem[]>([]);
  const loading = ref(false);

  // ── Reads ────────────────────────────────────────────────────────────
  async function fetchEngines() {
    loading.value = true;
    try {
      const res = await api.listEngines();
      engines.value = res.items;
    } finally { loading.value = false; }
  }
  async function fetchRules(engine?: string, q?: string) {
    loading.value = true;
    try {
      const res = await api.listRules(engine, q);
      rules.value = res.items;
    } finally { loading.value = false; }
  }
  async function fetchPolicies() {
    loading.value = true;
    try {
      const res = await api.listPolicies();
      policies.value = res.items;
    } finally { loading.value = false; }
  }
  async function fetchQueue(status = 'all') {
    loading.value = true;
    try {
      const res = await api.listQueue(status);
      queue.value = res.items;
    } finally { loading.value = false; }
  }
  async function cancelScan(id: string) {
    const res = await api.cancelScan(id);
    await fetchQueue();
    return res;
  }

  // ── Tool-call mutators ───────────────────────────────────────────────
  // toggleEngine: PATCH the engine row, then patch the in-memory cache
  // so the switch UI flips immediately without re-fetching the list.
  async function toggleEngine(id: string, enabled: boolean) {
    const res = await api.toggleEngine(id, enabled);
    const idx = engines.value.findIndex((e) => e.id === id);
    if (idx >= 0) engines.value[idx] = { ...engines.value[idx], enabled: res.enabled };
    return res;
  }

  // runHealthCheck: server writes a fresh engine_health_checks row +
  // bumps engines.health_status + last_health_check_at. We re-fetch
  // engines so the card's timestamp + tag update together.
  async function runHealthCheck(id: string) {
    const res = await api.healthCheck(id);
    await fetchEngines();
    return res;
  }

  // syncRules: server bumps detection.rules.updated_at. We re-fetch
  // the rules tab too so the search/filter view reflects the bump.
  async function syncRules(id: string) {
    const res = await api.syncEngine(id);
    await fetchRules();
    return res;
  }

  // triggerScan: server inserts a fresh snapshot + scan_runs row.
  // We re-fetch the queue so the new run appears at the top.
  async function triggerScan(body: { projectId: string; incremental?: boolean }) {
    const res = await api.triggerScan(body);
    await fetchQueue();
    return res;
  }

  return {
    engines, rules, policies, queue, loading,
    fetchEngines, fetchRules, fetchPolicies, fetchQueue, cancelScan,
    toggleEngine, runHealthCheck, syncRules, triggerScan,
  };
});