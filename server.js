/**
 * @fileoverview Servidor Full-Stack Node.js para o FinGuard AI.
 * Serve a interface de engenharia em Dark Mode e expõe endpoints REST de backend
 * para processamento de lotes, sanitização PII (LGPD) e auditoria com Google Gemini API.
 */

import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { INITIAL_BATCH_TRANSACTIONS } from './src/domain/mockTransactions.js';
import { FINGUARD_AUDIT_JSON_SCHEMA } from './src/domain/models.js';
import {
  preprocessAndMaskBatch,
  runFinGuardBatchPipeline,
} from './src/services/finopsPipelineService.js';
import { GEMINI_MODEL_ID } from './src/services/geminiFraudService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT || 3000);

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(payload, null, 2));
}

async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf-8');
  return raw ? JSON.parse(raw) : {};
}

export const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

  // 1. Healthcheck & Security Architecture Status
  if (req.method === 'GET' && url.pathname === '/api/health') {
    return sendJson(res, 200, {
      service: 'FinGuard AI — Conciliação Financeira, PII Masking & Detecção de Fraudes',
      status: 'HEALTHY',
      ai_model: GEMINI_MODEL_ID,
      security_gateway: 'LGPD_ART_46_ZERO_PII_LEAKAGE',
      audit_table: 'tb_finops_audit_logs',
      schema_contract: FINGUARD_AUDIT_JSON_SCHEMA,
      timestamp: new Date().toISOString(),
    });
  }

  // 2. Endpoint para inspecionar o lote inicial de 15 transações (Antes e Depois do PII Masking)
  if (req.method === 'GET' && url.pathname === '/api/transactions/initial-batch') {
    const maskedBatch = preprocessAndMaskBatch(INITIAL_BATCH_TRANSACTIONS);
    return sendJson(res, 200, {
      batch_size: maskedBatch.length,
      items: maskedBatch,
    });
  }

  // 3. Endpoint para executar a auditoria completa de lote via Backend
  if (req.method === 'POST' && url.pathname === '/api/audit/batch') {
    try {
      const body = await readJsonBody(req);
      const transactions =
        Array.isArray(body.transactions) && body.transactions.length > 0
          ? body.transactions
          : INITIAL_BATCH_TRANSACTIONS;
      const apiKey = body.apiKey || process.env.GEMINI_API_KEY || '';

      const result = await runFinGuardBatchPipeline(transactions, {
        apiKey,
        simulateRetryOnFirst: Boolean(body.simulateRetryOnFirst),
      });

      return sendJson(res, 200, result);
    } catch (error) {
      return sendJson(res, 500, {
        error: 'BATCH_AUDIT_ERROR',
        message: error.message,
      });
    }
  }

  // 4. Servidor de Arquivos Estáticos (Frontend ES Modules)
  let relativePath = url.pathname === '/' ? '/index.html' : url.pathname;
  const safeSuffix = path.normalize(relativePath).replace(/^(\.\.(\/|\\|$))+/, '');
  const filePath = path.join(__dirname, safeSuffix);

  try {
    const stat = await fs.stat(filePath);
    if (stat.isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';
      const content = await fs.readFile(filePath);
      res.writeHead(200, {
        'Content-Type': contentType,
        'X-Content-Type-Options': 'nosniff',
      });
      res.end(content);
      return;
    }
  } catch {
    // Arquivo não encontrado
  }

  sendJson(res, 404, { error: 'NOT_FOUND', path: url.pathname });
});

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  server.listen(PORT, () => {
    console.log(
      `[FinGuard AI] Servidor de Engenharia Financeira & Compliance rodando em http://localhost:${PORT}`
    );
  });
}
