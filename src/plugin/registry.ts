/**
 * Plugin Registry — Discovers, loads, and manages plugins
 * 
 * Inspired by garak's plugin discovery system where plugins are
 * registered by category and discovered at runtime.
 */

import type {
  Plugin, PluginId, PluginPhase, PluginState, PluginMeta,
  PluginFactory, RegistryEntry, ProbePlugin, DetectorPlugin, GeneratorPlugin,
} from './types.js';

export class PluginRegistry {
  private entries = new Map<PluginId, RegistryEntry>();
  private instances = new Map<PluginId, Plugin>();

  register(meta: PluginMeta, factory: PluginFactory): void {
    if (this.entries.has(meta.id)) {
      throw new Error(`Plugin already registered: ${meta.id}`);
    }
    this.entries.set(meta.id, { meta, factory });
  }

  unregister(id: PluginId): void {
    this.entries.delete(id);
    const instance = this.instances.get(id);
    if (instance) {
      instance.state = 'disabled';
      this.instances.delete(id);
    }
  }

  async load(id: PluginId, config?: Record<string, unknown>): Promise<Plugin> {
    const existing = this.instances.get(id);
    if (existing && existing.state === 'ready') return existing;

    const entry = this.entries.get(id);
    if (!entry) throw new Error(`Plugin not found: ${id}`);

    const plugin = entry.factory();
    await plugin.init({ ...entry.meta.defaultConfig, ...config });
    plugin.state = 'ready';
    this.instances.set(id, plugin);
    return plugin;
  }

  async loadAll(configs?: Record<PluginId, Record<string, unknown>>): Promise<void> {
    const promises: Promise<void>[] = [];
    for (const [id, entry] of this.entries) {
      if (entry.meta.phase === 'probe' || entry.meta.phase === 'detector' || entry.meta.phase === 'generator') {
        const config = configs?.[id];
        promises.push(
          this.load(id, config).then(() => {})
        );
      }
    }
    await Promise.all(promises);
  }

  async unload(id: PluginId): Promise<void> {
    const instance = this.instances.get(id);
    if (instance) {
      await instance.destroy();
      instance.state = 'uninitialized';
      this.instances.delete(id);
    }
  }

  async unloadAll(): Promise<void> {
    const promises = Array.from(this.instances.keys()).map(id => this.unload(id));
    await Promise.all(promises);
  }

  getInstance<T extends Plugin>(id: PluginId): T | undefined {
    return this.instances.get(id) as T | undefined;
  }

  getProbe(id: PluginId): ProbePlugin | undefined {
    return this.getInstance<ProbePlugin>(id);
  }

  getDetector(id: PluginId): DetectorPlugin | undefined {
    return this.getInstance<DetectorPlugin>(id);
  }

  getGenerator(id: PluginId): GeneratorPlugin | undefined {
    return this.getInstance<GeneratorPlugin>(id);
  }

  getByPhase(phase: PluginPhase): PluginMeta[] {
    return Array.from(this.entries.values())
      .filter(e => e.meta.phase === phase)
      .map(e => e.meta);
  }

  getByTag(tag: string): PluginMeta[] {
    return Array.from(this.entries.values())
      .filter(e => e.meta.tags.includes(tag))
      .map(e => e.meta);
  }

  getByLanguage(language: string): PluginMeta[] {
    return Array.from(this.entries.values())
      .filter(e => e.meta.languages.length === 0 || e.meta.languages.includes(language))
      .map(e => e.meta);
  }

  getAll(): PluginMeta[] {
    return Array.from(this.entries.values()).map(e => e.meta);
  }

  has(id: PluginId): boolean {
    return this.entries.has(id);
  }

  get size(): number {
    return this.entries.size;
  }

  get loadedCount(): number {
    let count = 0;
    for (const instance of this.instances.values()) {
      if (instance.state === 'ready' || instance.state === 'running') count++;
    }
    return count;
  }
}
