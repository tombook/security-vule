/**
 * Plugin Pipeline — Orchestrates probe → detector → generator execution
 *
 * Executes all registered probes in parallel, passes findings to detectors,
 * then optionally enhances results through generators (e.g. LLM).
 */

import type {
  ProbePlugin, DetectorPlugin, GeneratorPlugin,
  ProbeContext, DetectorContext, GeneratorContext,
  ProbeFinding, Detection, PipelineResult, PluginId,
} from './types.js';
import { PluginRegistry } from './registry.js';

export interface PipelineConfig {
  probeIds?: PluginId[];
  detectorIds?: PluginId[];
  generatorIds?: PluginId[];
  probeConfig?: Record<PluginId, Record<string, unknown>>;
  detectorConfig?: Record<PluginId, Record<string, unknown>>;
  generatorConfig?: Record<PluginId, Record<string, unknown>>;
  minConfidence?: number;
  language?: string;
}

const DEFAULT_CONFIG: PipelineConfig = {
  minConfidence: 0.3,
};

export class PluginPipeline {
  constructor(private registry: PluginRegistry) {}

  async run(code: string, filePath?: string, userConfig?: Partial<PipelineConfig>): Promise<PipelineResult> {
    const config = { ...DEFAULT_CONFIG, ...userConfig };
    const errors: Array<{ plugin: PluginId; error: string }> = [];
    const startTime = Date.now();

    const sharedData = new Map<string, unknown>();

    const probeCtx: ProbeContext = {
      code,
      language: config.language,
      filePath,
      config: config.probeConfig ?? {},
      sharedData,
    };

    const probeStart = Date.now();
    const findings = await this.runProbes(probeCtx, config.probeIds, errors);
    const probeTime = Date.now() - probeStart;

    const detectorCtx: DetectorContext = {
      findings,
      code,
      config: config.detectorConfig ?? {},
    };

    const detectorStart = Date.now();
    let detections = await this.runDetectors(detectorCtx, config.detectorIds, errors);
    const detectorTime = Date.now() - detectorStart;

    if (config.minConfidence) {
      detections = detections.filter(d => d.confidence >= config.minConfidence!);
    }

    const generatorCtx: GeneratorContext = {
      detections,
      code,
      config: config.generatorConfig ?? {},
    };

    const generatorStart = Date.now();
    const enhancedDetections = await this.runGenerators(generatorCtx, config.generatorIds, errors);
    const generatorTime = Date.now() - generatorStart;

    return {
      findings,
      detections,
      enhancedDetections,
      timing: {
        probes: probeTime,
        detectors: detectorTime,
        generators: generatorTime,
        total: Date.now() - startTime,
      },
      errors,
    };
  }

  private async runProbes(
    ctx: ProbeContext,
    ids: PluginId[] | undefined,
    errors: Array<{ plugin: PluginId; error: string }>,
  ): Promise<ProbeFinding[]> {
    const probeMetas = ids
      ? ids.map(id => this.registry.getProbe(id)).filter((p): p is ProbePlugin => p != null)
      : this.getLoadedProbes();

    const allFindings: ProbeFinding[] = [];

    const results = await Promise.allSettled(
      probeMetas.map(async (probe) => {
        probe.state = 'running';
        try {
          const probeCtx: ProbeContext = {
            ...ctx,
            config: { ...ctx.config, ...this.registry.getAll().find(m => m.id === probe.meta.id)?.defaultConfig },
          };
          const findings = await probe.execute(probeCtx);
          probe.state = 'ready';
          return findings;
        } catch (err) {
          probe.state = 'error';
          errors.push({ plugin: probe.meta.id, error: String(err) });
          return [] as ProbeFinding[];
        }
      }),
    );

    for (const result of results) {
      if (result.status === 'fulfilled') {
        allFindings.push(...result.value);
      }
    }

    return allFindings;
  }

  private async runDetectors(
    ctx: DetectorContext,
    ids: PluginId[] | undefined,
    errors: Array<{ plugin: PluginId; error: string }>,
  ): Promise<Detection[]> {
    const detectorMetas = ids
      ? ids.map(id => this.registry.getDetector(id)).filter((d): d is DetectorPlugin => d != null)
      : this.getLoadedDetectors();

    const allDetections: Detection[] = [];

    const results = await Promise.allSettled(
      detectorMetas.map(async (detector) => {
        detector.state = 'running';
        try {
          const detections = await detector.execute(ctx);
          detector.state = 'ready';
          return detections;
        } catch (err) {
          detector.state = 'error';
          errors.push({ plugin: detector.meta.id, error: String(err) });
          return [] as Detection[];
        }
      }),
    );

    for (const result of results) {
      if (result.status === 'fulfilled') {
        allDetections.push(...result.value);
      }
    }

    return allDetections;
  }

  private async runGenerators(
    ctx: GeneratorContext,
    ids: PluginId[] | undefined,
    errors: Array<{ plugin: PluginId; error: string }>,
  ): Promise<Detection[]> {
    if (!ids || ids.length === 0) return [];

    const generatorMetas = ids
      .map(id => this.registry.getGenerator(id))
      .filter((g): g is GeneratorPlugin => g != null);

    if (generatorMetas.length === 0) return ctx.detections;

    const allEnhanced: Detection[] = [];

    const results = await Promise.allSettled(
      generatorMetas.map(async (gen) => {
        gen.state = 'running';
        try {
          const enhanced = await gen.execute(ctx);
          gen.state = 'ready';
          return enhanced;
        } catch (err) {
          gen.state = 'error';
          errors.push({ plugin: gen.meta.id, error: String(err) });
          return ctx.detections;
        }
      }),
    );

    for (const result of results) {
      if (result.status === 'fulfilled') {
        allEnhanced.push(...result.value);
      }
    }

    return allEnhanced.length > 0 ? allEnhanced : ctx.detections;
  }

  private getLoadedProbes(): ProbePlugin[] {
    const probes: ProbePlugin[] = [];
    for (const meta of this.registry.getByPhase('probe')) {
      const p = this.registry.getProbe(meta.id);
      if (p) probes.push(p);
    }
    return probes;
  }

  private getLoadedDetectors(): DetectorPlugin[] {
    const detectors: DetectorPlugin[] = [];
    for (const meta of this.registry.getByPhase('detector')) {
      const d = this.registry.getDetector(meta.id);
      if (d) detectors.push(d);
    }
    return detectors;
  }
}
