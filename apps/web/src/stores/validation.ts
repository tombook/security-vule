import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import * as api from '@/api/validation';
import type { PocRun, ExecutionResult, ChatMessage } from '@/api/validation';

export const useValidationStore = defineStore('validation', () => {
  const queue = ref<PocRun[]>([]);
  const currentPoc = ref<PocRun | null>(null);
  const currentExecution = ref<ExecutionResult | null>(null);
  const chatMessages = ref<ChatMessage[]>([]);
  const library = ref<api.PocLibraryItem[]>([]);
  const loading = ref(false);
  const executing = ref(false);

  const pendingCount = computed(() => queue.value.filter((p) => p.status === 'pending').length);
  const runningCount = computed(() => queue.value.filter((p) => p.status === 'approved' || p.status === 'running').length);
  const provenCount = computed(() => queue.value.filter((p) => p.exploitProven).length);

  async function fetchQueue(status = 'all') {
    loading.value = true;
    try {
      const res = await api.listQueue(status);
      queue.value = res.items;
    } finally {
      loading.value = false;
    }
  }

  async function fetchPoc(id: string) {
    loading.value = true;
    try {
      currentPoc.value = await api.getPocRun(id);
    } finally {
      loading.value = false;
    }
  }

  async function fetchChat(pocRunId: string) {
    const res = await api.listChatMessages(pocRunId);
    chatMessages.value = res.items;
  }

  async function sendMessage(pocRunId: string, message: string) {
    const res = await api.postChatMessage(pocRunId, message);
    chatMessages.value = [...chatMessages.value, res.user, res.assistant];
  }

  async function generate(findingId: string) {
    loading.value = true;
    try {
      return await api.generatePoc(findingId);
    } finally {
      loading.value = false;
    }
  }

  async function approve(id: string, comment?: string) {
    const res = await api.approvePoc(id, comment);
    if (currentPoc.value?.id === id) {
      await fetchPoc(id);
    }
    return res;
  }

  async function reject(id: string, reason: string) {
    const res = await api.rejectPoc(id, reason);
    if (currentPoc.value?.id === id) {
      await fetchPoc(id);
    }
    return res;
  }

  async function execute(id: string) {
    executing.value = true;
    try {
      currentExecution.value = await api.executePoc(id);
      await fetchPoc(id);
      return currentExecution.value;
    } finally {
      executing.value = false;
    }
  }

  async function fetchLibrary() {
    const res = await api.listLibrary();
    library.value = res.items;
  }

  async function saveToLibrary(pocRunId: string, title: string, description?: string) {
    const item = await api.addToLibrary(pocRunId, title, description);
    library.value = [item, ...library.value];
    return item;
  }

  return {
    queue, currentPoc, currentExecution, chatMessages, library, loading, executing,
    pendingCount, runningCount, provenCount,
    fetchQueue, fetchPoc, fetchChat, sendMessage, generate, approve, reject, execute, fetchLibrary, saveToLibrary,
  };
});
