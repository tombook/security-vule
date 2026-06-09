/**
 * AI Bill of Materials (AI-BOM) — SBOM-style manifest for AI components.
 *
 * Compatible with CycloneDX 1.5 (https://cyclonedx.org/spec/cyclonedx-spec-1.5)
 * for the "ai" component type. Standard SBOM consumers (e.g. dependency-track)
 * can ingest this file to track which AI models are in use and their
 * security posture.
 */

export type AIComponentType = 'llm' | 'embedding-model' | 'classifier' | 'vector-store';
export type ProviderPrivacy = 'local' | 'no-train-opt-in' | 'no-train-mandatory' | 'train-opt-out' | 'train-default';
export type Deployment = 'cloud' | 'self-hosted' | 'edge' | 'embedded';

export interface AIComponent {
  type: AIComponentType;
  name: string;
  version?: string;
  provider: string;
  privacy: ProviderPrivacy;
  deployment: Deployment;
  dataResidency?: string;
  complianceCertifications?: string[];
  rateLimit?: { tokens?: number; costUsd?: number; calls?: number };
  riskScore?: number;
  notes?: string;
}

export interface AIBom {
  bomFormat: 'CycloneDX-AI';
  specVersion: '1.5';
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
  };
  tools: {
    vendor: string;
    name: string;
    version: string;
  };
  component: {
    type: 'application';
    name: string;
    version: string;
    'bom-ref': string;
  };
  components: AIComponent[];
}

type ProviderMeta = Pick<AIComponent, 'privacy' | 'deployment' | 'dataResidency' | 'complianceCertifications' | 'riskScore' | 'notes'>;

const PROVIDER_REGISTRY: Record<string, ProviderMeta> = {
  'zhipu:glm-5.1': { privacy: 'no-train-mandatory', deployment: 'cloud', dataResidency: 'CN', complianceCertifications: ['ISO 27001'], riskScore: 60 },
  'anthropic:claude-sonnet-4-5': { privacy: 'no-train-mandatory', deployment: 'cloud', dataResidency: 'US', complianceCertifications: ['SOC 2 Type II', 'HIPAA-eligible'], riskScore: 40 },
  'openai:gpt-4o': { privacy: 'no-train-opt-in', deployment: 'cloud', dataResidency: 'US', complianceCertifications: ['SOC 2'], riskScore: 50 },
  'openai:gpt-4o-mini': { privacy: 'no-train-opt-in', deployment: 'cloud', dataResidency: 'US', complianceCertifications: ['SOC 2'], riskScore: 30 },
  'ollama:qwen2.5': { privacy: 'local', deployment: 'self-hosted', dataResidency: 'local', complianceCertifications: [], riskScore: 10 },
  'ollama:llama3.3': { privacy: 'local', deployment: 'self-hosted', dataResidency: 'local', complianceCertifications: [], riskScore: 10 },
  'deepseek:deepseek-chat': { privacy: 'no-train-mandatory', deployment: 'cloud', dataResidency: 'CN', complianceCertifications: [], riskScore: 70 },
  'mock:mock': { privacy: 'local', deployment: 'embedded', dataResidency: 'local', complianceCertifications: [], riskScore: 0, notes: 'Deterministic mock provider for testing — no LLM call' },
};

export function aiComponentFromProvider(provider: string, model: string, rateLimit?: AIComponent['rateLimit']): AIComponent {
  const key = `${provider}:${model}`;
  const meta: Partial<ProviderMeta> = PROVIDER_REGISTRY[key] ?? {};
  return {
    type: 'llm',
    name: model,
    provider,
    privacy: meta.privacy ?? 'no-train-mandatory',
    deployment: meta.deployment ?? 'cloud',
    dataResidency: meta.dataResidency,
    complianceCertifications: meta.complianceCertifications,
    riskScore: meta.riskScore,
    rateLimit,
    notes: meta.notes,
  };
}

export function buildAIBom(
  appName: string,
  appVersion: string,
  components: AIComponent[],
  toolsVendor: string = 'security-vule',
  toolsName: string = 'security-vule',
  toolsVersion: string = '0.1.0',
): AIBom {
  const serial = `urn:uuid:${randomSerial()}`;
  return {
    bomFormat: 'CycloneDX-AI',
    specVersion: '1.5',
    serialNumber: serial,
    version: 1,
    metadata: { timestamp: new Date().toISOString() },
    tools: { vendor: toolsVendor, name: toolsName, version: toolsVersion },
    component: {
      type: 'application',
      name: appName,
      version: appVersion,
      'bom-ref': `urn:app:${appName}:${appVersion}`,
    },
    components,
  };
}

function randomSerial(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export function formatAIBomTable(bom: AIBom): string {
  const lines: string[] = [
    `## AI Bill of Materials`,
    ``,
    `Format: ${bom.bomFormat} ${bom.specVersion}`,
    `Serial: ${bom.serialNumber}`,
    `Application: ${bom.component.name} v${bom.component.version}`,
    `Generated: ${bom.metadata.timestamp}`,
    ``,
    `| Provider | Model | Type | Privacy | Deployment | Residency | Compliance | Risk |`,
    `|---|---|---|---|---|---|---|---|`,
  ];
  for (const c of bom.components) {
    lines.push(`| ${c.provider} | ${c.name} | ${c.type} | ${c.privacy} | ${c.deployment} | ${c.dataResidency ?? '-'} | ${(c.complianceCertifications ?? []).join(', ') || '-'} | ${c.riskScore ?? '-'} |`);
  }
  return lines.join('\n');
}
