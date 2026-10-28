/**
 * @fileoverview Camada de Persistência e Auditoria Local (`tb_finops_audit_logs`).
 * Implementa armazenamento estruturado em IndexedDB com espelhamento resiliente em LocalStorage
 * (e fallback em memória para execução em Node.js / testes automatizados), simulando fielmente
 * a tabela relacional SQL `tb_finops_audit_logs`.
 */

const DB_NAME = 'FinGuardAuditDB';
const DB_VERSION = 1;
export const SQL_TABLE_NAME = 'tb_finops_audit_logs';
const LOCAL_STORAGE_KEY = 'finguard_tb_finops_audit_logs_v1';

/** Fallback em memória para ambientes headless/Node.js sem IndexedDB/LocalStorage */
let memoryStoreFallback = [];

/**
 * DDL SQL oficial da tabela `tb_finops_audit_logs` para inspeção e exportação de compliance.
 */
export const TB_FINOPS_AUDIT_LOGS_DDL = `CREATE TABLE IF NOT EXISTS tb_finops_audit_logs (
    audit_log_id           VARCHAR(64) PRIMARY KEY,
    transaction_id         VARCHAR(32) NOT NULL UNIQUE,
    order_id               VARCHAR(32) NOT NULL,
    transaction_type       VARCHAR(24) NOT NULL,
    merchant_id            VARCHAR(24) NOT NULL,
    merchant_name          VARCHAR(120) NOT NULL,
    gross_amount_brl       DECIMAL(12, 2) NOT NULL,
    net_settlement_brl     DECIMAL(12, 2) NOT NULL,
    refund_amount_brl      DECIMAL(12, 2) NOT NULL DEFAULT 0.00,
    coupon_code            VARCHAR(40) NULL,
    coupon_discount_brl    DECIMAL(12, 2) NOT NULL DEFAULT 0.00,
    masked_customer_cpf    VARCHAR(20) NOT NULL,
    masked_customer_email  VARCHAR(120) NOT NULL,
    masked_card_pan        VARCHAR(24) NOT NULL,
    cpf_correlation_hash   VARCHAR(32) NOT NULL,
    pii_zero_leak_verified BOOLEAN NOT NULL DEFAULT TRUE,
    deterministic_rules    JSONB NOT NULL,
    fraud_score            DECIMAL(5, 2) NOT NULL CHECK (fraud_score >= 0 AND fraud_score <= 100),
    anomaly_classification VARCHAR(40) NOT NULL,
    recommended_action     VARCHAR(32) NOT NULL,
    risk_indicators        JSONB NOT NULL,
    explainability_report  TEXT NOT NULL,
    ai_model_version       VARCHAR(48) NOT NULL,
    retry_attempts         INTEGER NOT NULL DEFAULT 1,
    inference_latency_ms   INTEGER NOT NULL,
    sanitized_payload_json JSONB NOT NULL,
    audit_contract_json    JSONB NOT NULL,
    created_at             TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);`;

/**
 * Abre conexão com o IndexedDB no navegador, criando a Object Store `tb_finops_audit_logs`
 * e índices secundários equivalentes aos índices de banco relacional.
 *
 * @returns {Promise<IDBDatabase | null>}
 */
function openAuditIndexedDB() {
  if (typeof indexedDB === 'undefined') {
    return Promise.resolve(null);
  }

  return new Promise((resolve) => {
    try {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(SQL_TABLE_NAME)) {
          const store = db.createObjectStore(SQL_TABLE_NAME, {
            keyPath: 'transaction_id',
          });
          store.createIndex('idx_anomaly_classification', 'anomaly_classification', {
            unique: false,
          });
          store.createIndex('idx_recommended_action', 'recommended_action', {
            unique: false,
          });
          store.createIndex('idx_fraud_score', 'fraud_score', { unique: false });
          store.createIndex('idx_created_at', 'created_at', { unique: false });
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

/**
 * Sincroniza os registros no LocalStorage para redundância e leitura instantânea.
 * @param {Array<object>} rows
 */
function writeMirrorStorage(rows) {
  memoryStoreFallback = Array.isArray(rows) ? [...rows] : [];
  if (typeof localStorage !== 'undefined') {
    try {
      localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(memoryStoreFallback));
    } catch {
      // Ignora erro de quota caso ocorra
    }
  }
}

/**
 * Lê os registros do LocalStorage ou fallback em memória.
 * @returns {Array<object>}
 */
function readMirrorStorage() {
  if (typeof localStorage !== 'undefined') {
    try {
      const raw = localStorage.getItem(LOCAL_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          memoryStoreFallback = parsed;
          return parsed;
        }
      }
    } catch {
      // Fallback para memória
    }
  }
  return [...memoryStoreFallback];
}

/**
 * Constrói uma linha padronizada da tabela `tb_finops_audit_logs` a partir dos resultados
 * das camadas de Segurança (PII Masking), Determinística e Inteligência Preditiva (Gemini).
 *
 * @param {{
 *   sanitizedTransaction: object,
 *   maskingDiff: Array<object>,
 *   securityAttestation: object,
 *   deterministicResult: object,
 *   structuredOutput: object,
 *   engineMetadata: object
 * }} params
 * @returns {object} Registro completo formatado como linha de `tb_finops_audit_logs`
 */
export function createAuditLogRecord({
  sanitizedTransaction,
  maskingDiff,
  securityAttestation,
  deterministicResult,
  structuredOutput,
  engineMetadata,
}) {
  const nowIso = new Date().toISOString();
  return {
    audit_log_id: `AUD-${sanitizedTransaction.transaction_id}-${Date.now().toString(36).toUpperCase()}`,
    transaction_id: sanitizedTransaction.transaction_id,
    order_id: sanitizedTransaction.order_id,
    timestamp: sanitizedTransaction.timestamp,
    transaction_type: sanitizedTransaction.transaction_type,
    merchant_id: sanitizedTransaction.merchant_id,
    merchant_name: sanitizedTransaction.merchant_name,
    gross_amount_brl: Number(sanitizedTransaction.gross_amount_brl),
    net_settlement_brl: Number(sanitizedTransaction.net_settlement_brl),
    refund_amount_brl: Number(sanitizedTransaction.refund_amount_brl || 0),
    coupon_code: sanitizedTransaction.coupon_code || null,
    coupon_discount_brl: Number(sanitizedTransaction.coupon_discount_brl || 0),
    masked_customer_name: sanitizedTransaction.customer_name,
    masked_customer_cpf: sanitizedTransaction.customer_cpf,
    masked_customer_email: sanitizedTransaction.customer_email,
    masked_customer_phone: sanitizedTransaction.customer_phone,
    masked_card_pan: sanitizedTransaction.card_number,
    cpf_correlation_hash: sanitizedTransaction.cpf_correlation_hash,
    card_correlation_hash: sanitizedTransaction.card_correlation_hash,
    pii_zero_leak_verified: Boolean(securityAttestation?.safe),
    pii_masked_fields_count: Number(securityAttestation?.maskedFieldsCount || 6),
    masking_diff: maskingDiff,
    deterministic_rules: deterministicResult.triggeredRules,
    deterministic_passed: deterministicResult.passedAllRules,
    fraud_score: Number(structuredOutput.fraud_score),
    anomaly_classification: structuredOutput.anomaly_classification,
    recommended_action: structuredOutput.recommended_action,
    risk_indicators: structuredOutput.risk_indicators,
    explainability_report: structuredOutput.explainability_report,
    ai_model_version: engineMetadata.mode,
    retry_attempts: engineMetadata.attempts,
    retries_used: engineMetadata.retriesUsed,
    inference_latency_ms: engineMetadata.latencyMs,
    sanitized_payload_json: sanitizedTransaction,
    audit_contract_json: structuredOutput,
    created_at: nowIso,
  };
}

/**
 * Insere ou atualiza (UPSERT) um registro na tabela `tb_finops_audit_logs`
 * (IndexedDB + LocalStorage Mirror).
 *
 * @param {object} auditRecord
 * @returns {Promise<object>}
 */
export async function saveAuditLogRecord(auditRecord) {
  const currentRows = readMirrorStorage();
  const existingIndex = currentRows.findIndex(
    (r) => r.transaction_id === auditRecord.transaction_id
  );
  if (existingIndex >= 0) {
    currentRows[existingIndex] = auditRecord;
  } else {
    currentRows.push(auditRecord);
  }
  writeMirrorStorage(currentRows);

  const db = await openAuditIndexedDB();
  if (db) {
    await new Promise((resolve) => {
      try {
        const tx = db.transaction([SQL_TABLE_NAME], 'readwrite');
        const store = tx.objectStore(SQL_TABLE_NAME);
        store.put(auditRecord);
        tx.oncomplete = () => {
          db.close();
          resolve(true);
        };
        tx.onerror = () => {
          db.close();
          resolve(false);
        };
      } catch {
        db.close();
        resolve(false);
      }
    });
  }

  return auditRecord;
}

/**
 * Lista todos os registros armazenados em `tb_finops_audit_logs`.
 * @returns {Promise<Array<object>>}
 */
export async function listAuditLogRecords() {
  const db = await openAuditIndexedDB();
  if (db) {
    const idbRows = await new Promise((resolve) => {
      try {
        const tx = db.transaction([SQL_TABLE_NAME], 'readonly');
        const store = tx.objectStore(SQL_TABLE_NAME);
        const req = store.getAll();
        req.onsuccess = () => {
          db.close();
          resolve(req.result || []);
        };
        req.onerror = () => {
          db.close();
          resolve(null);
        };
      } catch {
        db.close();
        resolve(null);
      }
    });

    if (Array.isArray(idbRows) && idbRows.length > 0) {
      writeMirrorStorage(idbRows);
      return idbRows.sort((a, b) => a.transaction_id.localeCompare(b.transaction_id));
    }
  }

  const fallbackRows = readMirrorStorage();
  return fallbackRows.sort((a, b) => a.transaction_id.localeCompare(b.transaction_id));
}

/**
 * Limpa todos os registros da tabela `tb_finops_audit_logs` (TRUNCATE TABLE).
 * @returns {Promise<void>}
 */
export async function clearAuditLogRecords() {
  writeMirrorStorage([]);
  const db = await openAuditIndexedDB();
  if (db) {
    await new Promise((resolve) => {
      try {
        const tx = db.transaction([SQL_TABLE_NAME], 'readwrite');
        tx.objectStore(SQL_TABLE_NAME).clear();
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.onerror = () => {
          db.close();
          resolve();
        };
      } catch {
        db.close();
        resolve();
      }
    });
  }
}

/**
 * Gera uma instrução SQL `INSERT INTO tb_finops_audit_logs` correspondente a um registro
 * auditado para inspeção de engenharia de dados e compliance.
 *
 * @param {object} row
 * @returns {string}
 */
export function formatRecordAsSqlInsert(row) {
  const esc = (str) => String(str ?? '').replace(/'/g, "''");
  return `INSERT INTO ${SQL_TABLE_NAME} (
  audit_log_id, transaction_id, order_id, transaction_type, merchant_id, merchant_name,
  gross_amount_brl, net_settlement_brl, refund_amount_brl, coupon_code, coupon_discount_brl,
  masked_customer_cpf, masked_customer_email, masked_card_pan, cpf_correlation_hash,
  pii_zero_leak_verified, deterministic_rules, fraud_score, anomaly_classification,
  recommended_action, risk_indicators, explainability_report, ai_model_version,
  retry_attempts, inference_latency_ms, audit_contract_json, created_at
) VALUES (
  '${esc(row.audit_log_id)}',
  '${esc(row.transaction_id)}',
  '${esc(row.order_id)}',
  '${esc(row.transaction_type)}',
  '${esc(row.merchant_id)}',
  '${esc(row.merchant_name)}',
  ${Number(row.gross_amount_brl).toFixed(2)},
  ${Number(row.net_settlement_brl).toFixed(2)},
  ${Number(row.refund_amount_brl).toFixed(2)},
  ${row.coupon_code ? `'${esc(row.coupon_code)}'` : 'NULL'},
  ${Number(row.coupon_discount_brl).toFixed(2)},
  '${esc(row.masked_customer_cpf)}',
  '${esc(row.masked_customer_email)}',
  '${esc(row.masked_card_pan)}',
  '${esc(row.cpf_correlation_hash)}',
  TRUE,
  '${esc(JSON.stringify(row.deterministic_rules))} '::jsonb,
  ${Number(row.fraud_score).toFixed(2)},
  '${esc(row.anomaly_classification)}',
  '${esc(row.recommended_action)}',
  '${esc(JSON.stringify(row.risk_indicators))}'::jsonb,
  '${esc(row.explainability_report)}',
  '${esc(row.ai_model_version)}',
  ${Number(row.retry_attempts || 1)},
  ${Number(row.inference_latency_ms || 0)},
  '${esc(JSON.stringify(row.audit_contract_json))}'::jsonb,
  '${esc(row.created_at)}'
);`;
}
