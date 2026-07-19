import { pool, type PoolClient } from '../db/client';

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system' | 'tool';
  content: string;
  createdAt: string;
  promptTokens: number;
  completionTokens: number;
}

export async function listMessages(pocRunId: string, tenantId: string): Promise<ChatMessage[]> {
  const client = await pool.connect();
  try {
    const { rows } = await client.query(
      `SELECT id, role, content, occurred_at, prompt_tokens, completion_tokens
       FROM poc.poc_chat_messages
       WHERE poc_run_id = $1 AND tenant_id = $2
       ORDER BY occurred_at ASC`,
      [pocRunId, tenantId],
    );
    return rows.map((r: any) => ({
      id: r.id,
      role: r.role,
      content: r.content,
      createdAt: r.occurred_at,
      promptTokens: r.prompt_tokens,
      completionTokens: r.completion_tokens,
    }));
  } finally {
    client.release();
  }
}

export async function postMessage(
  pocRunId: string,
  tenantId: string,
  customerId: string,
  projectId: string,
  role: 'user' | 'assistant',
  content: string,
  clientOverride?: PoolClient,
): Promise<ChatMessage> {
  const useProvided = !!clientOverride;
  const client = clientOverride ?? await pool.connect();
  try {
    const threadId = pocRunId;
    const promptTokens = Math.ceil(content.length / 4);
    const completionTokens = role === 'assistant' ? Math.ceil(content.length / 3) : 0;

    const { rows } = await client.query(
      `INSERT INTO poc.poc_chat_messages
         (tenant_id, customer_id, project_id, poc_run_id, thread_id, role, content,
          prompt_tokens, completion_tokens, model, occurred_at)
       VALUES
         ($1, $2, $3, $4, $5, $6::chat_role_enum, $7, $8, $9, 'security-vule-poc-v1', NOW())
       RETURNING id, role, content, occurred_at, prompt_tokens, completion_tokens`,
      [tenantId, customerId, projectId, pocRunId, threadId, role, content, promptTokens, completionTokens],
    );
    return {
      id: rows[0].id,
      role: rows[0].role,
      content: rows[0].content,
      createdAt: rows[0].occurred_at,
      promptTokens: rows[0].prompt_tokens,
      completionTokens: rows[0].completion_tokens,
    };
  } finally {
    if (!useProvided) client.release();
  }
}

export async function autoAssistantReply(
  pocRunId: string,
  tenantId: string,
  customerId: string,
  projectId: string,
  userQuestion: string,
  scriptContext: string,
): Promise<ChatMessage> {
  const lower = userQuestion.toLowerCase();
  let reply: string;
  if (lower.includes('simplify') || lower.includes('shorter')) {
    const lines = scriptContext.split('\n').slice(0, 8).join('\n');
    reply = `Simplified version:\n\n\`\`\`python\n${lines}\n# ... (truncated)\n\`\`\``;
  } else if (lower.includes('why') || lower.includes('explain')) {
    reply = `The PoC exploits the vulnerable parameter with a payload designed to trigger the specific sink. The key insight is that user input is concatenated without sanitization, allowing arbitrary execution. The script first probes for the vulnerability, then validates the exploit by checking for expected side effects.`;
  } else if (lower.includes('risk') || lower.includes('safe')) {
    reply = `This PoC is designed to run in an ISOLATED sandbox container with no network access and resource limits. It does NOT contact the target directly from your network; the sandbox is the only point of contact. The script is read-only review-only until you explicitly approve execution.`;
  } else {
    reply = `I understand the question. Let me explain the PoC structure: it sends a crafted payload to ${projectId ? 'the project endpoint' : 'the target URL'}, then checks the response for signs of successful exploitation. Would you like me to simplify the script, explain the vulnerability deeper, or add more safety checks?`;
  }
  return postMessage(pocRunId, tenantId, customerId, projectId, 'assistant', reply);
}
