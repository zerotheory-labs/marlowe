const { test } = require('node:test');
const assert = require('node:assert/strict');
const { validateSettings, streamCompletion, discoverModels, scanLocalRuntimes, testModelConnection } = require('../electron/provider.cjs');

test('endpoint validation allows secure and loopback endpoints only', () => {
  assert.deepEqual(validateSettings({ baseUrl: 'https://example.com/v1/', model: ' model ' }), { baseUrl: 'https://example.com/v1', model: 'model' });
  assert.equal(validateSettings({ baseUrl: 'http://localhost:11434/v1', model: 'local' }).model, 'local');
  for (const baseUrl of ['http://remote.example/v1', 'file:///tmp/model', 'https://user:pass@example.com', 'https://example.com/?token=secret']) assert.throws(() => validateSettings({ baseUrl, model: 'test' }));
  assert.throws(() => validateSettings({ baseUrl: 'https://example.com', model: '' }));
});
function chunksResponse(chunks) {
  return new Response(new ReadableStream({ start(controller) { for (const chunk of chunks) controller.enqueue(new TextEncoder().encode(chunk)); controller.close(); } }), { headers: { 'Content-Type': 'text/event-stream' } });
}
const options = { settings: { baseUrl: 'https://example.com/v1', model: 'test' }, apiKey: 'secret', messages: [{ role: 'user', content: 'Hello' }], context: '', signal: new AbortController().signal, onToken() {} };
test('handles fragmented SSE records, CRLF, comments, and final unterminated line', async () => {
  const tokens = []; let request;
  const result = await streamCompletion({ ...options, onToken: token => tokens.push(token), fetchImpl: async (url, init) => {
    request = { url, ...init };
    return chunksResponse([': heartbeat\r\ndata: {"cho', 'ices":[{"delta":{"content":"Hi "}}]}\r\n\r\ndata: {"choices":[{"delta":{"content":"there"}}]}\n\ndata: [DONE]']);
  } });
  assert.equal(result, 'Hi there'); assert.deepEqual(tokens, ['Hi ', 'there']);
  assert.equal(request.url, 'https://example.com/v1/chat/completions'); assert.equal(request.headers.Authorization, 'Bearer secret');
  assert.equal(request.redirect, 'error');
  assert.equal(JSON.parse(request.body).messages.length, 2);
});
test('terminal output is included only when explicitly provided', async () => {
  let payload;
  await streamCompletion({ ...options, context: 'untrusted terminal text', fetchImpl: async (_url, init) => { payload = JSON.parse(init.body); return chunksResponse(['data: {"choices":[{"delta":{"content":"ok"}}]}\n']); } });
  assert.match(payload.messages[1].content, /untrusted terminal text/); assert.equal(payload.messages[1].role, 'user');
});
test('errors give actionable feedback without echoing provider secrets', async () => {
  await assert.rejects(streamCompletion({ ...options, fetchImpl: async () => new Response('secret details', { status: 401 }) }), /HTTP 401/);
  await assert.rejects(streamCompletion({ ...options, fetchImpl: async () => chunksResponse(['data: [DONE]\n']) }), /No text received/);
  await assert.rejects(streamCompletion({ ...options, fetchImpl: async () => chunksResponse(['data: invalid-json\n']) }), /invalid streaming response/);
  await assert.rejects(streamCompletion({ ...options, fetchImpl: async () => chunksResponse(['data: {"error":{"message":"secret"}}\n']) }), /streaming error/);
});

test('discoverModels, scanLocalRuntimes, and testModelConnection enrich Ollama tags and verify SSE streaming', async () => {
  const discovered = await discoverModels({
    baseUrl: 'http://127.0.0.1:11434/v1',
    fetchImpl: async url => {
      if (url.endsWith('/v1/models')) {
        return new Response(JSON.stringify({ data: [{ id: 'qwen3-vl:8b-instruct' }, { id: 'qwen2.5-coder:14b' }] }));
      }
      if (url.endsWith('/api/tags')) {
        return new Response(JSON.stringify({
          models: [
            { name: 'qwen3-vl:8b-instruct', size: 5400000000, details: { parameter_size: '8.2B', quantization_level: 'Q4_K_M', families: ['qwen3vl', 'clip'] } },
            { name: 'qwen2.5-coder:14b', size: 9100000000, details: { parameter_size: '14.8B', quantization_level: 'Q4_K_M', families: ['qwen2'] } }
          ]
        }));
      }
      throw new Error('Unexpected URL ' + url);
    }
  });
  assert.equal(discovered.models.length, 2);
  assert.equal(discovered.models[0].isVision, true);
  assert.equal(discovered.models[0].parameterSize, '8.2B');
  assert.equal(discovered.models[1].isVision, false);

  const radar = await scanLocalRuntimes({
    fetchImpl: async url => url.includes('11434')
      ? new Response(JSON.stringify({ data: [{ id: 'qwen2.5-coder:14b' }] }))
      : Promise.reject(new Error('ECONNREFUSED'))
  });
  assert.equal(radar.runtimes.find(r => r.id === 'ollama').online, true);
  assert.equal(radar.runtimes.find(r => r.id === 'lmstudio').online, false);

  const ping = await testModelConnection({
    baseUrl: 'http://127.0.0.1:11434/v1',
    model: 'qwen2.5-coder:14b',
    fetchImpl: async () => chunksResponse(['data: {"choices":[{"delta":{"content":"OK"}}]}\n\ndata: [DONE]\n'])
  });
  assert.equal(ping.ok, true);
  assert.ok(ping.latencyMs >= 1);

  // Anthropic headers (x-api-key + anthropic-version) & Gemini models/ prefix stripping
  let anthropicHeaders = null;
  const claudeModels = await discoverModels({
    baseUrl: 'https://api.anthropic.com/v1',
    apiKey: 'sk-ant-test-key',
    fetchImpl: async (_url, init) => {
      anthropicHeaders = init.headers;
      return new Response(JSON.stringify({ data: [{ id: 'claude-sonnet-4-0' }, { id: 'claude-opus-4-1' }] }));
    }
  });
  assert.equal(anthropicHeaders['x-api-key'], 'sk-ant-test-key');
  assert.equal(anthropicHeaders['anthropic-version'], '2023-06-01');
  assert.equal(claudeModels.models[0].id, 'claude-sonnet-4-0');

  const geminiModels = await discoverModels({
    baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai',
    apiKey: 'AIzaTest',
    fetchImpl: async () => new Response(JSON.stringify({ data: [{ id: 'models/gemini-2.5-pro' }, { id: 'models/text-embedding-004' }] }))
  });
  assert.deepEqual(geminiModels.models.map(m => m.id), ['gemini-2.5-pro']);
});
