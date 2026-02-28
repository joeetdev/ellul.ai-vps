/**
 * Thread SSE Handler
 *
 * Encapsulates all per-thread SSE observation for OpenCode.
 * One instance per active OpenCode request. Self-healing connection
 * with strict session isolation.
 *
 * Thread-scoped guarantees:
 * - readonly sessionId — immutable binding
 * - private response state — cannot leak between threads
 * - reconnectSSE() auto-heals on blips (500ms, max 10 retries)
 * - every log tagged [SSE][thread=XX,session=YY]
 */

import * as http from 'http';
import { OPENCODE_API_PORT, CLI_TIMEOUT_MS } from '../config';
import { addThinkingStep, broadcastToSubscribers } from './processing-state';
import { addMessage } from './thread.service';

// WebSocket client interface
interface WsClient {
  send(data: string): void;
}

// Response structure
export interface CliResponse {
  reasoning: string[];
  text: string[];
  tools: string[];
}

// Build ?directory= query string for OpenCode API
function opencodeDirectoryParam(project?: string | null): string {
  const PROJECTS_DIR = '/home/' + (process.env.USER || 'dev') + '/projects';
  const directory = project ? `${PROJECTS_DIR}/${project}` : PROJECTS_DIR;
  return '?directory=' + encodeURIComponent(directory);
}

function sendThinkingStep(ws: WsClient, content: string, threadId?: string | null): void {
  if (threadId) {
    addThinkingStep(threadId, content);
  } else {
    try {
      ws.send(JSON.stringify({ type: 'thinking_step', content, threadId, timestamp: Date.now() }));
    } catch {}
  }
}

export class ThreadSSEHandler {
  // Immutable thread binding
  readonly threadId: string;
  readonly sessionId: string;
  private readonly ws: WsClient;
  private readonly project: string | null;
  private readonly message: string;

  // Private per-thread state
  private readonly response: CliResponse = { reasoning: [], text: [], tools: [] };
  private eventReq: http.ClientRequest | null = null;
  private settled = false;
  private promptSent = false;
  private reconnectCount = 0;
  private readonly MAX_RECONNECTS = 10;
  private sseBuffer = '';
  private reasoningBuffer = '';
  private lastMeaningfulEventAt = Date.now();
  private stallTimer: ReturnType<typeof setInterval> | null = null;
  private eventCount = 0;
  private reasoningCount = 0;
  private retryCount = 0;
  private readonly MAX_RETRIES_BEFORE_ERROR = 5;
  private readonly STALL_TIMEOUT_MS = 60000;

  // Question handling
  private pendingQuestion: {
    questionId: string;
    questions: Array<{ question: string; options: Array<{ label: string; description?: string }> }>;
    timer: ReturnType<typeof setTimeout>;
  } | null = null;

  // Promise control
  private resolve!: (value: CliResponse) => void;
  private reject!: (reason: Error) => void;

  constructor(
    threadId: string,
    sessionId: string,
    ws: WsClient,
    project: string | null,
    message: string,
  ) {
    this.threadId = threadId;
    this.sessionId = sessionId;
    this.ws = ws;
    this.project = project;
    this.message = message;
  }

  private log(msg: string): void {
    console.log(`[SSE][thread=${this.threadId.substring(0, 8)},session=${this.sessionId.substring(0, 12)}] ${msg}`);
  }

  private warn(msg: string): void {
    console.warn(`[SSE][thread=${this.threadId.substring(0, 8)},session=${this.sessionId.substring(0, 12)}] ${msg}`);
  }

  private error(msg: string): void {
    console.error(`[SSE][thread=${this.threadId.substring(0, 8)},session=${this.sessionId.substring(0, 12)}] ${msg}`);
  }

  /**
   * Execute the SSE streaming request. Returns when the session goes idle
   * or an unrecoverable error occurs.
   */
  execute(): Promise<CliResponse> {
    return new Promise((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
      this.connectSSE();
    });
  }

  /**
   * Answer a pending question from the frontend.
   * Returns true if a question was pending and answered.
   */
  answerQuestion(value: string): boolean {
    if (!this.pendingQuestion) return false;

    const pending = this.pendingQuestion;
    clearTimeout(pending.timer);
    this.pendingQuestion = null;

    // Map option number back to label
    const optionIdx = parseInt(value, 10) - 1;
    const firstQuestion = pending.questions[0];
    const selectedLabel = firstQuestion?.options?.[optionIdx]?.label || value;

    this.log(`User answered question: "${selectedLabel}". Aborting stuck session and re-prompting...`);

    // Step 1: Reply to question API (clears the pending question state)
    const answers = pending.questions.map((q) => {
      const match = q.options?.find(o => o.label === selectedLabel);
      return [match?.label || selectedLabel];
    });
    const replyData = JSON.stringify({ answers });
    const replyReq = http.request({
      hostname: '127.0.0.1',
      port: OPENCODE_API_PORT,
      path: `/question/${pending.questionId}/reply`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(replyData) },
    }, (res) => { res.resume(); });
    replyReq.on('error', () => {});
    replyReq.write(replyData);
    replyReq.end();

    // Step 2: Abort the stuck session (after a brief delay for the reply to settle)
    setTimeout(() => {
      this.log(`Aborting session after question reply`);
      const abortReq = http.request({
        hostname: '127.0.0.1',
        port: OPENCODE_API_PORT,
        path: `/session/${this.sessionId}/abort`,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': 2 },
      }, (res) => {
        res.resume();
        this.log(`Abort status: ${res.statusCode}`);

        // Step 3: Wait for session to go idle, then re-prompt with answer baked in
        setTimeout(() => {
          const questionText = firstQuestion?.question || 'your question';
          const newMessage = `The user was asked: "${questionText}" and chose: "${selectedLabel}". Now proceed with that choice. Original request: ${this.message}`;

          this.log(`Re-prompting with answer baked in`);
          const dirParam = this.project ? `?directory=${encodeURIComponent('/home/' + (process.env.USER || 'dev') + '/projects/' + this.project)}` : '';
          const promptData = JSON.stringify({ parts: [{ type: 'text', text: newMessage }] });
          const promptReq = http.request({
            hostname: '127.0.0.1',
            port: OPENCODE_API_PORT,
            path: `/session/${this.sessionId}/prompt_async${dirParam}`,
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(promptData) },
          }, (res) => {
            res.resume();
            this.log(`Re-prompt status: ${res.statusCode}`);
            // Reset stall timer
            this.lastMeaningfulEventAt = Date.now();
          });
          promptReq.on('error', (err) => this.error(`Re-prompt error: ${err.message}`));
          promptReq.write(promptData);
          promptReq.end();
        }, 1500);
      });
      abortReq.on('error', (err) => this.error(`Abort error: ${err.message}`));
      abortReq.write('{}');
      abortReq.end();
    }, 500);

    return true;
  }

  hasPendingQuestion(): boolean {
    return this.pendingQuestion !== null;
  }

  /**
   * Destroy handler: clean up all resources and resolve with partial response.
   */
  destroy(): void {
    this.finish();
  }

  // --- Private methods ---

  private connectSSE(): void {
    this.sseBuffer = '';
    this.log(`Connecting SSE (attempt ${this.reconnectCount + 1})`);

    this.eventReq = http.get(
      {
        hostname: '127.0.0.1',
        port: OPENCODE_API_PORT,
        path: '/global/event',
        headers: { Accept: 'text/event-stream' },
      },
      (eventRes) => {
        if (eventRes.statusCode !== 200) {
          this.error(`SSE status: ${eventRes.statusCode}`);
          eventRes.resume();
          // On first connect failure, reject (caller handles fallback)
          if (this.reconnectCount === 0 && !this.settled) {
            this.settled = true;
            this.reject(new Error('SSE connection failed'));
          }
          return;
        }
        this.log('SSE connected');
        // Reset reconnect count on successful connection
        this.reconnectCount = 0;

        eventRes.on('data', (chunk: Buffer) => {
          if (this.settled) return;
          this.sseBuffer += chunk.toString();
          const events = this.sseBuffer.split('\n\n');
          this.sseBuffer = events.pop() || '';

          for (const event of events) {
            if (this.settled) break;
            const lines = event.split('\n');
            let eventData = '';
            for (const line of lines) {
              if (line.startsWith('data: ')) {
                eventData += line.slice(6);
              }
            }
            if (!eventData) continue;
            try {
              const raw = JSON.parse(eventData);
              const parsed = raw.payload || raw;
              this.handleEvent(parsed);
            } catch {
              // Ignore parse errors
            }
          }
        });

        eventRes.on('error', (err) => {
          this.warn(`SSE stream error: ${err.message}`);
          if (!this.settled) this.reconnectSSE();
        });

        eventRes.on('end', () => {
          this.warn('SSE stream ended');
          if (!this.settled) this.reconnectSSE();
        });
      }
    );

    this.eventReq.on('error', (err) => {
      this.error(`SSE connection error: ${err.message}`);
      if (!this.settled) this.reconnectSSE();
    });
  }

  private reconnectSSE(): void {
    this.reconnectCount++;
    if (this.reconnectCount > this.MAX_RECONNECTS) {
      this.warn(`Max reconnects (${this.MAX_RECONNECTS}) exhausted, finishing with partial response`);
      this.finish();
      return;
    }

    // Destroy old connection
    if (this.eventReq) {
      try { this.eventReq.destroy(); } catch {}
      this.eventReq = null;
    }
    this.sseBuffer = '';

    this.log(`Reconnecting in 500ms (attempt ${this.reconnectCount}/${this.MAX_RECONNECTS})`);
    setTimeout(() => {
      if (!this.settled) {
        this.connectSSE();
      }
    }, 500);
  }

  private handleEvent(parsed: any): void {
    this.eventCount++;

    // server.connected — send prompt (only once)
    if (parsed.type === 'server.connected' && !this.promptSent) {
      this.promptSent = true;
      this.log('SSE ready - sending prompt_async');
      this.startStallDetector();
      this.sendPromptAsync();
      return;
    }

    // Log first few events
    if (this.eventCount <= 5) {
      this.log(`Event #${this.eventCount}: type=${parsed.type}, partType=${parsed.properties?.part?.type || 'n/a'}, sessionID=${parsed.properties?.part?.sessionID?.substring(0, 12) || parsed.properties?.sessionID?.substring(0, 12) || 'n/a'}`);
    }

    // message.part.updated / message.part.completed — accumulate response
    if ((parsed.type === 'message.part.updated' || parsed.type === 'message.part.completed') && parsed.properties?.part) {
      const part = parsed.properties.part;
      // STRICT session filter
      const eventSessionId = part.sessionID || parsed.properties?.sessionID;
      if (!eventSessionId || eventSessionId !== this.sessionId) {
        if (this.eventCount <= 3) this.log(`Skipping event: eventSessionID=${(eventSessionId || 'none').substring?.(0, 12) || 'none'} !== our session`);
        return;
      }
      const delta = parsed.properties.delta || '';
      const partType = part.type || '';
      this.lastMeaningfulEventAt = Date.now();

      if (partType === 'reasoning' || partType === 'thinking') {
        this.reasoningCount++;
        if (delta && delta.trim()) {
          this.reasoningBuffer += delta;
          if (this.reasoningBuffer.length > 20 || delta.match(/[.!?;:\n]\s*$/)) {
            this.response.reasoning.push(this.reasoningBuffer.trim());
            sendThinkingStep(this.ws, this.reasoningBuffer.trim(), this.threadId);
            this.reasoningBuffer = '';
          }
        } else if (part.text && part.text.trim()) {
          this.response.reasoning.push(part.text.trim());
          sendThinkingStep(this.ws, part.text.trim(), this.threadId);
        }
        if (this.reasoningCount === 1) {
          this.log(`First reasoning: delta="${(delta || '').substring(0, 50)}", buffer="${this.reasoningBuffer.substring(0, 50)}"`);
        }
      } else if (partType === 'text') {
        if (delta) {
          if (this.response.text.length === 0) this.response.text.push('');
          this.response.text[this.response.text.length - 1] += delta;
        } else if (part.text) {
          if (this.response.text.length === 0) this.response.text.push(part.text);
          else this.response.text[this.response.text.length - 1] = part.text;
        }
      } else if (partType === 'tool') {
        const toolName = part.tool || 'tool';
        if (!this.response.tools.includes(toolName)) this.response.tools.push(toolName);
        const toolStatus = part.state?.status || 'running';
        if (toolStatus === 'running' || toolStatus === 'completed') {
          const label = toolStatus === 'completed' ? `${toolName} done` : `Using ${toolName}...`;
          sendThinkingStep(this.ws, label, this.threadId);
        }
      } else if (partType === 'step-start' || partType === 'step-finish') {
        // Step lifecycle events — no display needed
      } else if (partType !== '') {
        const content = (delta || part.text || part.content || '').trim();
        if (content) {
          this.response.reasoning.push(content);
          sendThinkingStep(this.ws, content, this.threadId);
        }
      }
    }

    // session.idle — response complete
    if (parsed.type === 'session.idle' && parsed.properties?.sessionID === this.sessionId) {
      this.log('Session idle - response complete');
      this.finish();
      return;
    }

    // session.status
    if (parsed.type === 'session.status' && parsed.properties?.sessionID === this.sessionId) {
      const status = parsed.properties.status as { type?: string; message?: string; attempt?: number } | undefined;
      if (status?.type === 'idle') {
        this.log('Session status idle - response complete');
        this.finish();
        return;
      }
      if (status?.type === 'retry' && status.message) {
        this.retryCount++;
        const isRateLimit = /rate.?limit|429|too many requests/i.test(status.message);
        this.warn(`Retry #${this.retryCount}: attempt=${status.attempt}, msg=${status.message.substring(0, 120)}`);

        if (isRateLimit && this.retryCount >= this.MAX_RETRIES_BEFORE_ERROR) {
          this.error(`Rate limit retries exhausted (${this.retryCount}), aborting`);
          if (!this.settled) {
            this.settled = true;
            if (this.stallTimer) { clearInterval(this.stallTimer); this.stallTimer = null; }
            if (this.eventReq) { try { this.eventReq.destroy(); } catch {} }
            this.reject(new Error('Rate limit reached for this model. Try switching to a different model.'));
          }
          return;
        }

        const retryMsg = isRateLimit
          ? `Rate limit hit (attempt ${status.attempt || '?'}). Retrying...`
          : `Retrying (attempt ${status.attempt || '?'})...`;
        sendThinkingStep(this.ws, retryMsg, this.threadId);
      }
    }

    // question.asked — forward to frontend
    if (parsed.type === 'question.asked' && parsed.properties?.sessionID === this.sessionId) {
      const qProps = parsed.properties as { id: string; questions: Array<{ question: string; options: Array<{ label: string; description?: string }> }> };
      const questionId = qProps.id;
      const questions = qProps.questions || [];
      const firstQuestion = questions[0];

      if (this.threadId && firstQuestion?.options?.length) {
        const options = firstQuestion.options.map((opt: { label: string; description?: string }, i: number) => ({
          number: String(i + 1),
          label: opt.label,
          description: opt.description || '',
        }));
        const context = firstQuestion.question || 'Please select an option:';

        this.log(`Forwarding question ${questionId}: ${options.length} options`);

        broadcastToSubscribers(this.threadId, {
          type: 'cli_prompt',
          session: 'opencode',
          context,
          options,
          selectionType: 'number',
          inChatAuth: false,
          threadId: this.threadId,
          timestamp: Date.now(),
        });

        addMessage(this.threadId, {
          type: 'cli_prompt',
          content: context,
          session: 'opencode',
          model: null,
          thinking: null,
          metadata: { options, selectionType: 'number', inChatAuth: false },
        });

        sendThinkingStep(this.ws, 'Waiting for your choice...', this.threadId);

        // Auto-answer after 2 minutes
        const autoAnswerTimer = setTimeout(() => {
          if (this.pendingQuestion) {
            this.log(`Question ${questionId} timed out, auto-answering with first option`);
            this.answerQuestion('1');
          }
        }, 120000);

        this.pendingQuestion = { questionId, questions, timer: autoAnswerTimer };
      } else {
        // No threadId or no options — auto-answer via abort+re-prompt
        const selectedLabel = firstQuestion?.options?.[0]?.label || 'yes';
        this.log(`Auto-answering question ${questionId} (no thread): ${selectedLabel}`);

        const answers = questions.map((q: { options?: Array<{ label: string }> }) => [q.options?.[0]?.label || 'yes']);
        const replyData = JSON.stringify({ answers });
        const replyReq = http.request({
          hostname: '127.0.0.1',
          port: OPENCODE_API_PORT,
          path: `/question/${questionId}/reply`,
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(replyData) },
        }, (res) => { res.resume(); });
        replyReq.on('error', () => {});
        replyReq.write(replyData);
        replyReq.end();

        setTimeout(() => {
          const abortReq = http.request({
            hostname: '127.0.0.1', port: OPENCODE_API_PORT,
            path: `/session/${this.sessionId}/abort`, method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': 2 },
          }, (res) => {
            res.resume();
            setTimeout(() => {
              const questionText = firstQuestion?.question || 'your question';
              const newMsg = `The user chose: "${selectedLabel}" for "${questionText}". Proceed with that choice. Original request: ${this.message}`;
              const dirParam = this.project ? `?directory=${encodeURIComponent('/home/' + (process.env.USER || 'dev') + '/projects/' + this.project)}` : '';
              const promptData = JSON.stringify({ parts: [{ type: 'text', text: newMsg }] });
              const promptReq = http.request({
                hostname: '127.0.0.1', port: OPENCODE_API_PORT,
                path: `/session/${this.sessionId}/prompt_async${dirParam}`, method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(promptData) },
              }, (res2) => { res2.resume(); this.lastMeaningfulEventAt = Date.now(); });
              promptReq.on('error', () => {});
              promptReq.write(promptData);
              promptReq.end();
            }, 1500);
          });
          abortReq.on('error', () => {});
          abortReq.write('{}');
          abortReq.end();
        }, 500);
      }
    }

    // permission.asked — auto-grant
    if (parsed.type === 'permission.asked' && parsed.properties?.sessionID === this.sessionId) {
      const permId = (parsed.properties as { id: string }).id;
      const permName = (parsed.properties as { permission?: string }).permission || 'unknown';
      this.log(`Auto-granting permission ${permId}: ${permName}`);
      const replyData = JSON.stringify({ reply: 'always' });
      const replyReq = http.request({
        hostname: '127.0.0.1',
        port: OPENCODE_API_PORT,
        path: `/permission/${permId}/reply`,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(replyData) },
      }, (res) => { res.resume(); this.log(`Permission reply status: ${res.statusCode}`); });
      replyReq.on('error', (err) => this.error(`Permission reply error: ${err.message}`));
      replyReq.write(replyData);
      replyReq.end();
    }

    // session.error
    if (parsed.type === 'session.error' && parsed.properties?.sessionID === this.sessionId) {
      const errMsg = parsed.properties?.error || 'Session error';
      this.error(`Session error: ${errMsg}`);
      if (!this.settled) {
        this.settled = true;
        if (this.stallTimer) { clearInterval(this.stallTimer); this.stallTimer = null; }
        if (this.eventReq) { try { this.eventReq.destroy(); } catch {} }
        this.reject(new Error('OpenCode: ' + errMsg));
      }
    }
  }

  private sendPromptAsync(): void {
    const dirParam = opencodeDirectoryParam(this.project);
    const postData = JSON.stringify({ parts: [{ type: 'text', text: this.message }] });
    const asyncPath = `/session/${this.sessionId}/prompt_async${dirParam}`;
    this.log(`POST ${asyncPath}`);

    const msgReq = http.request(
      {
        hostname: '127.0.0.1',
        port: OPENCODE_API_PORT,
        path: asyncPath,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
        },
      },
      (msgRes) => {
        msgRes.resume();
        this.log(`prompt_async status: ${msgRes.statusCode}`);
        if (msgRes.statusCode !== 204 && msgRes.statusCode !== 200) {
          this.error(`prompt_async unexpected status: ${msgRes.statusCode}`);
          // Non-success — let the caller handle fallback via rejection
          if (!this.settled) {
            this.settled = true;
            if (this.stallTimer) { clearInterval(this.stallTimer); this.stallTimer = null; }
            if (this.eventReq) { try { this.eventReq.destroy(); } catch {} }
            this.reject(new Error('prompt_async failed'));
          }
        }
      }
    );
    msgReq.on('error', (err) => {
      this.error(`prompt_async error: ${err.message}`);
      if (!this.settled) {
        this.settled = true;
        if (this.stallTimer) { clearInterval(this.stallTimer); this.stallTimer = null; }
        if (this.eventReq) { try { this.eventReq.destroy(); } catch {} }
        this.reject(new Error('prompt_async failed: ' + err.message));
      }
    });
    msgReq.setTimeout(CLI_TIMEOUT_MS);
    msgReq.write(postData);
    msgReq.end();
  }

  private startStallDetector(): void {
    this.stallTimer = setInterval(() => {
      if (this.settled) { if (this.stallTimer) clearInterval(this.stallTimer); return; }
      if (Date.now() - this.lastMeaningfulEventAt > this.STALL_TIMEOUT_MS) {
        this.warn(`Stall detected (${Math.round((Date.now() - this.lastMeaningfulEventAt) / 1000)}s without events), finishing`);
        if (this.stallTimer) clearInterval(this.stallTimer);
        this.finish();
      }
    }, 10000);
  }

  private finish(): void {
    if (this.settled) return;
    this.settled = true;

    if (this.stallTimer) { clearInterval(this.stallTimer); this.stallTimer = null; }
    if (this.eventReq) { try { this.eventReq.destroy(); } catch {} }

    // Clean up pending question
    if (this.pendingQuestion) {
      clearTimeout(this.pendingQuestion.timer);
      this.pendingQuestion = null;
    }

    // Flush remaining reasoning buffer
    if (this.reasoningBuffer.trim()) {
      this.response.reasoning.push(this.reasoningBuffer.trim());
      sendThinkingStep(this.ws, this.reasoningBuffer.trim(), this.threadId);
      this.reasoningBuffer = '';
    }

    this.log(`Complete: ${this.eventCount} events, ${this.reasoningCount} reasoning, ${this.response.text.length} text, ${this.response.tools.length} tools`);
    this.resolve(this.response);
  }
}
