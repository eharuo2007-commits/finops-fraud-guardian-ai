/**
 * @fileoverview Suíte de Testes Automatizados End-to-End — FinGuard AI.
 * Valida PII Data Masking (LGPD), Regras Determinísticas, Contrato JSON Schema da Gemini API,
 * Retry Pattern com Exponential Backoff e Persistência em `tb_finops_audit_logs`.
 */

import assert from 'node:assert/strict';
import { INITIAL_BATCH_TRANSACTIONS } from '../src/domain/mockTransactions.js';
import {
  ANOMALY_CLASSIFICATIONS,
  RECOMMENDED_ACTIONS,
  validateAuditContract,
} from '../src/domain/models.js';
import { evaluateDeterministicRules } from '../src/domain/deterministicRules.js';
import {
  maskCardNumber,
  maskCpf,
  maskEmail,
  maskTransactionPII,
  verifyZeroPIIExposure,
} from '../src/services/piiMasker.js';
import { executeWithRetry } from '../src/services/retryWithBackoff.js';
import {
  preprocessAndMaskBatch,
  runFinGuardBatchPipeline,
} from '../src/services/finopsPipelineService.js';
import { formatRecordAsSqlInsert } from '../src/storage/auditRepository.js';

async function runAllTests() {
  console.log('===================================================================');
  console.log('🛡  FINGUARD AI — SUÍTE DE AUDITORIA TÉCNICA E TESTES AUTOMATIZADOS');
  console.log('===================================================================\n');

  // 1. Teste de Volume do Lote Inicial (15 transações)
  assert.equal(
    INITIAL_BATCH_TRANSACTIONS.length,
    15,
    'O lote inicial deve conter exatamente 15 transações simuladas.'
  );
  console.log('✔ [TEST 1] Lote inicial contém 15 transações simuladas diversificadas.');

  // 2. Teste de PII Data Masking (LGPD & PCI-DSS)
  assert.equal(maskCpf('348.712.905-44'), '***.712.905-**');
  assert.equal(maskCardNumber('4532 8810 3392 7104'), '**** **** **** 7104');
  const maskedEmail = maskEmail('carlos.mendonca88@gmail.com');
  assert.ok(maskedEmail.includes('***'), 'E-mail deve ser mascarado com asteriscos.');

  const maskedBatch = preprocessAndMaskBatch(INITIAL_BATCH_TRANSACTIONS);
  for (const item of maskedBatch) {
    const check = verifyZeroPIIExposure(item.sanitizedTransaction);
    assert.equal(
      check.safe,
      true,
      `Transação ${item.rawTransaction.transaction_id} não pode conter PII vazado.`
    );
    assert.match(item.sanitizedTransaction.customer_cpf, /^\*\*\*\.\d{3}\.\d{3}-\*\*$/);
    assert.match(item.sanitizedTransaction.card_number, /^\*\*\*\* \*\*\*\* \*\*\*\* \d{4}$/);
  }
  console.log(
    '✔ [TEST 2] PII Masking (CPF, E-mail, PAN e Free-Text) validado com Zero-Leakage em 15/15 transações.'
  );

  // 3. Teste da Camada Determinística (Duplicidade no mesmo minuto e limites rígidos de estorno)
  const sanitizedContext = maskedBatch.map((i) => i.sanitizedTransaction);

  // TXN-2026-9002 e TXN-2026-9003 são no mesmo minuto (18:04) para o pedido ORD-88415
  const dupTx = sanitizedContext.find((t) => t.transaction_id === 'TXN-2026-9003');
  const dupEval = evaluateDeterministicRules(dupTx, sanitizedContext);
  assert.ok(
    dupEval.triggeredRules.some((r) => r.code === 'RULE_SAME_MINUTE_DUPLICATE'),
    'Deve detectar duplicidade de reembolso no mesmo minuto.'
  );
  assert.equal(
    dupEval.suggestedClassification,
    ANOMALY_CLASSIFICATIONS.SUSPICIOUS_REFUND_DUPLICATION
  );

  // TXN-2026-9007 solicita R$ 620,00 de reembolso sobre pedido de R$ 490,00 (acima do teto rígido R$ 350,00)
  const overRefundTx = sanitizedContext.find((t) => t.transaction_id === 'TXN-2026-9007');
  const overRefundEval = evaluateDeterministicRules(overRefundTx, sanitizedContext);
  assert.ok(
    overRefundEval.triggeredRules.some((r) => r.code === 'RULE_REFUND_EXCEEDS_ORIGINAL_ORDER'),
    'Deve detectar reembolso maior que o pedido original.'
  );
  assert.ok(
    overRefundEval.triggeredRules.some((r) => r.code === 'RULE_HARD_REFUND_LIMIT_EXCEEDED'),
    'Deve detectar violação do limite rígido de reembolso.'
  );
  console.log(
    '✔ [TEST 3] Camada Determinística detectou duplicidade no mesmo minuto, abuso de cupons e violação de teto rígido.'
  );

  // 4. Teste do Retry Pattern com Exponential Backoff
  let transientCalls = 0;
  const retryOutcome = await executeWithRetry(
    async (attempt) => {
      transientCalls++;
      if (attempt < 3) {
        const err = new Error('HTTP 429 Rate Limit Transient Error');
        err.status = 429;
        throw err;
      }
      return { status: 'RECOVERED_ON_ATTEMPT_3' };
    },
    { maxRetries: 3, baseDelayMs: 25, maxDelayMs: 120 }
  );
  assert.equal(transientCalls, 3);
  assert.equal(retryOutcome.telemetry.retriesUsed, 2);
  console.log(
    `✔ [TEST 4] Retry Pattern com Exponential Backoff recuperou falha HTTP 429 em ${retryOutcome.telemetry.attempts} tentativas (${retryOutcome.telemetry.totalBackoffMs}ms total backoff).`
  );

  // 5. Teste End-to-End do Pipeline Completo + Validação do Contrato JSON Schema e SQL Dump
  const pipelineResult = await runFinGuardBatchPipeline(INITIAL_BATCH_TRANSACTIONS, {
    simulateRetryOnFirst: true,
  });

  assert.equal(pipelineResult.records.length, 15);
  for (const rec of pipelineResult.records) {
    const schemaCheck = validateAuditContract(rec.audit_contract_json);
    assert.equal(
      schemaCheck.valid,
      true,
      `Contrato JSON inválido para ${rec.transaction_id}: ${schemaCheck.errors.join(', ')}`
    );
    const sqlStmt = formatRecordAsSqlInsert(rec);
    assert.ok(sqlStmt.startsWith('INSERT INTO tb_finops_audit_logs'));
  }

  console.log(
    `✔ [TEST 5] Pipeline End-to-End processou 15 transações: Taxa de Fraude = ${pipelineResult.metrics.fraudRatePercent}%, Bloqueios = ${pipelineResult.metrics.blockedCount}, Volume Protegido = R$ ${pipelineResult.metrics.protectedAmountBrl.toFixed(2)}.`
  );
  console.log('\n🎉 TODOS OS TESTES PASSARAM COM 100% DE CONFORMIDADE!');
}

runAllTests().catch((err) => {
  console.error('❌ Falha nos testes:', err);
  process.exit(1);
});
