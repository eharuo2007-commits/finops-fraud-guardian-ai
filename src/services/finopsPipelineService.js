/**
 * @fileoverview Orquestrador do Pipeline FinGuard AI (Ingestão → PII Masking →
 * Regras Determinísticas → Inferência Estruturada Gemini API → Persistência `tb_finops_audit_logs`).
 */

import { evaluateDeterministicRules } from '../domain/deterministicRules.js';
import { ANOMALY_CLASSIFICATIONS, RECOMMENDED_ACTIONS } from '../domain/models.js';
import { createAuditLogRecord, saveAuditLogRecord } from '../storage/auditRepository.js';
import { analyzeTransactionWithGemini } from './geminiFraudService.js';
import { maskTransactionPII } from './piiMasker.js';

/**
 * Pré-processa um lote bruto de transações executando o PII Data Masking (LGPD)
 * e validando que nenhum dado sensível permaneceu exposto.
 *
 * @param {Array<object>} rawTransactions
 * @returns {Array<{
 *   rawTransaction: object,
 *   sanitizedTransaction: object,
 *   maskingDiff: Array<object>,
 *   securityAttestation: object
 * }>}
 */
export function preprocessAndMaskBatch(rawTransactions) {
  return rawTransactions.map((rawTx) => {
    const { sanitizedTransaction, maskingDiff, securityAttestation } = maskTransactionPII(rawTx);
    return {
      rawTransaction: rawTx,
      sanitizedTransaction,
      maskingDiff,
      securityAttestation,
    };
  });
}

/**
 * Executa o pipeline completo de conciliação e detecção de fraude sobre um lote pré-mascarado,
 * emitindo callbacks de progresso em tempo real para a UI de Engenharia.
 *
 * @param {Array<object>} rawTransactions Lote de transações brutas
 * @param {{
 *   apiKey?: string,
 *   simulateRetryOnFirst?: boolean,
 *   onProgress?: (progress: { index: number, total: number, record: object, stage: string }) => void,
 *   onRetryEvent?: (retryEvent: object) => void
 * }} [options]
 * @returns {Promise<{ records: Array<object>, maskedBatch: Array<object>, metrics: object }>}
 */
export async function runFinGuardBatchPipeline(rawTransactions, options = {}) {
  const maskedBatch = preprocessAndMaskBatch(rawTransactions);
  const sanitizedContext = maskedBatch.map((item) => item.sanitizedTransaction);
  const persistedRecords = [];

  for (let i = 0; i < maskedBatch.length; i++) {
    const item = maskedBatch[i];
    const { sanitizedTransaction, maskingDiff, securityAttestation } = item;

    // 1. Camada Determinística (Regras de Negócio Financeiras)
    const deterministicResult = evaluateDeterministicRules(sanitizedTransaction, sanitizedContext);

    // 2. Camada Preditiva (Google Gemini API Structured Outputs + Retry Pattern)
    const { structuredOutput, engineMetadata } = await analyzeTransactionWithGemini(
      sanitizedTransaction,
      deterministicResult,
      {
        apiKey: options.apiKey,
        simulateTransientFailureOnce: Boolean(options.simulateRetryOnFirst && i === 0),
        onRetry: (retryInfo) => {
          if (typeof options.onRetryEvent === 'function') {
            options.onRetryEvent({
              transaction_id: sanitizedTransaction.transaction_id,
              ...retryInfo,
            });
          }
        },
      }
    );

    // 3. Persistência Estruturada (`tb_finops_audit_logs`)
    const auditRecord = createAuditLogRecord({
      sanitizedTransaction,
      maskingDiff,
      securityAttestation,
      deterministicResult,
      structuredOutput,
      engineMetadata,
    });

    await saveAuditLogRecord(auditRecord);
    persistedRecords.push(auditRecord);

    if (typeof options.onProgress === 'function') {
      options.onProgress({
        index: i + 1,
        total: maskedBatch.length,
        record: auditRecord,
        stage: 'PERSISTED',
      });
    }
  }

  const metrics = computeFinOpsMetrics(persistedRecords);
  return {
    records: persistedRecords,
    maskedBatch,
    metrics,
  };
}

/**
 * Calcula os KPIs executivos e operacionais do Dashboard de Compliance & Métricas FinOps.
 *
 * @param {Array<object>} auditRecords Registros da tabela `tb_finops_audit_logs`
 * @returns {object}
 */
export function computeFinOpsMetrics(auditRecords = []) {
  const totalCount = auditRecords.length;
  if (totalCount === 0) {
    return {
      totalTransactedBrl: 0,
      totalRefundRequestedBrl: 0,
      protectedAmountBrl: 0,
      analyzedCount: 0,
      fraudDetectedCount: 0,
      fraudRatePercent: 0,
      blockedCount: 0,
      holdForAuditCount: 0,
      approvedCount: 0,
      avgFraudScore: 0,
      avgLatencyMs: 0,
      totalRetriesExecuted: 0,
      piiMaskedFieldsTotal: 0,
      byClassification: {
        [ANOMALY_CLASSIFICATIONS.NORMAL]: 0,
        [ANOMALY_CLASSIFICATIONS.SUSPICIOUS_REFUND_DUPLICATION]: 0,
        [ANOMALY_CLASSIFICATIONS.COUPON_ABUSE]: 0,
        [ANOMALY_CLASSIFICATIONS.MERCHANT_DISCREPANCY]: 0,
        [ANOMALY_CLASSIFICATIONS.CRITICAL_FRAUD]: 0,
      },
      byAction: {
        [RECOMMENDED_ACTIONS.APPROVE]: 0,
        [RECOMMENDED_ACTIONS.HOLD_FOR_AUDIT]: 0,
        [RECOMMENDED_ACTIONS.AUTOMATIC_BLOCK]: 0,
        [RECOMMENDED_ACTIONS.MANUAL_REVIEW]: 0,
      },
    };
  }

  let totalTransactedBrl = 0;
  let totalRefundRequestedBrl = 0;
  let protectedAmountBrl = 0;
  let fraudDetectedCount = 0;
  let blockedCount = 0;
  let holdForAuditCount = 0;
  let approvedCount = 0;
  let scoreSum = 0;
  let latencySum = 0;
  let totalRetriesExecuted = 0;
  let piiMaskedFieldsTotal = 0;

  const byClassification = {
    [ANOMALY_CLASSIFICATIONS.NORMAL]: 0,
    [ANOMALY_CLASSIFICATIONS.SUSPICIOUS_REFUND_DUPLICATION]: 0,
    [ANOMALY_CLASSIFICATIONS.COUPON_ABUSE]: 0,
    [ANOMALY_CLASSIFICATIONS.MERCHANT_DISCREPANCY]: 0,
    [ANOMALY_CLASSIFICATIONS.CRITICAL_FRAUD]: 0,
  };

  const byAction = {
    [RECOMMENDED_ACTIONS.APPROVE]: 0,
    [RECOMMENDED_ACTIONS.HOLD_FOR_AUDIT]: 0,
    [RECOMMENDED_ACTIONS.AUTOMATIC_BLOCK]: 0,
    [RECOMMENDED_ACTIONS.MANUAL_REVIEW]: 0,
  };

  for (const row of auditRecords) {
    const gross = Number(row.gross_amount_brl || 0);
    const refund = Number(row.refund_amount_brl || 0);
    const discount = Number(row.coupon_discount_brl || 0);
    const net = Number(row.net_settlement_brl || 0);

    totalTransactedBrl += gross;
    totalRefundRequestedBrl += refund;
    scoreSum += Number(row.fraud_score || 0);
    latencySum += Number(row.inference_latency_ms || 0);
    totalRetriesExecuted += Number(row.retries_used || 0);
    piiMaskedFieldsTotal += Number(row.pii_masked_fields_count || 6);

    const cls = row.anomaly_classification;
    if (byClassification[cls] !== undefined) {
      byClassification[cls] += 1;
    }

    const act = row.recommended_action;
    if (byAction[act] !== undefined) {
      byAction[act] += 1;
    }

    if (cls !== ANOMALY_CLASSIFICATIONS.NORMAL) {
      fraudDetectedCount += 1;
      // Calcula o valor financeiro protegido (estorno evitado, desconto abusivo bloqueado ou excesso de repasse contido)
      const exposure =
        refund > 0 ? refund : discount > 0 ? discount : Math.max(0, net - gross * 0.88);
      protectedAmountBrl += exposure > 0 ? exposure : gross;
    }

    if (act === RECOMMENDED_ACTIONS.AUTOMATIC_BLOCK) {
      blockedCount += 1;
    } else if (
      act === RECOMMENDED_ACTIONS.HOLD_FOR_AUDIT ||
      act === RECOMMENDED_ACTIONS.MANUAL_REVIEW
    ) {
      holdForAuditCount += 1;
    } else if (act === RECOMMENDED_ACTIONS.APPROVE) {
      approvedCount += 1;
    }
  }

  return {
    totalTransactedBrl: Math.round(totalTransactedBrl * 100) / 100,
    totalRefundRequestedBrl: Math.round(totalRefundRequestedBrl * 100) / 100,
    protectedAmountBrl: Math.round(protectedAmountBrl * 100) / 100,
    analyzedCount: totalCount,
    fraudDetectedCount,
    fraudRatePercent: Math.round((fraudDetectedCount / totalCount) * 1000) / 10,
    blockedCount,
    holdForAuditCount,
    approvedCount,
    avgFraudScore: Math.round((scoreSum / totalCount) * 10) / 10,
    avgLatencyMs: Math.round(latencySum / totalCount),
    totalRetriesExecuted,
    piiMaskedFieldsTotal,
    byClassification,
    byAction,
  };
}
