/**
 * @fileoverview Camada Determinística (Regras de Negócio Financeiras & Anti-Fraude).
 * Executa validações matemáticas e temporais de latência sub-milissegundo ANTES da chamada
 * ao modelo preditivo Google Gemini API, compondo uma arquitetura híbrida Neuro-Simbólica.
 */

import {
  ANOMALY_CLASSIFICATIONS,
  DETERMINISTIC_POLICY_LIMITS,
  RECOMMENDED_ACTIONS,
  TRANSACTION_TYPES,
} from './models.js';

/**
 * Extrai a chave de minuto ISO (YYYY-MM-DDTHH:mm) e o epoch em segundos.
 * @param {string} isoTimestamp
 */
function parseTimestampWindow(isoTimestamp) {
  const date = new Date(isoTimestamp);
  const epochSeconds = Math.floor(date.getTime() / 1000);
  const minuteBucket = typeof isoTimestamp === 'string' ? isoTimestamp.slice(0, 16) : '';
  return { epochSeconds, minuteBucket };
}

/**
 * Avalia uma transação individual (já sanitizada) contra o contexto do lote
 * aplicando regras financeiras determinísticas estritas.
 *
 * @param {object} sanitizedTx Transação com PII mascarado
 * @param {Array<object>} batchContext Lista completa de transações sanitizadas do lote
 * @returns {{
 *   passedAllRules: boolean,
 *   deterministicScoreFloor: number,
 *   triggeredRules: Array<{ code: string, severity: 'CRITICAL' | 'HIGH' | 'MEDIUM', description: string }>,
 *   suggestedClassification: string,
 *   suggestedAction: string
 * }}
 */
export function evaluateDeterministicRules(sanitizedTx, batchContext = []) {
  const triggeredRules = [];
  let deterministicScoreFloor = 5.0;
  let suggestedClassification = ANOMALY_CLASSIFICATIONS.NORMAL;
  let suggestedAction = RECOMMENDED_ACTIONS.APPROVE;

  const { epochSeconds: txSeconds, minuteBucket: txMinute } = parseTimestampWindow(
    sanitizedTx.timestamp
  );

  // =========================================================================
  // REGRA 1: DETECÇÃO DE DUPLICIDADE DE TRANSAÇÃO NO MESMO MINUTO
  // =========================================================================
  const sameMinuteDuplicates = batchContext.filter((other) => {
    if (other.transaction_id === sanitizedTx.transaction_id) return false;
    if (other.transaction_type !== sanitizedTx.transaction_type) return false;

    const { epochSeconds: otherSeconds, minuteBucket: otherMinute } = parseTimestampWindow(
      other.timestamp
    );
    const withinSameMinute =
      otherMinute === txMinute ||
      Math.abs(txSeconds - otherSeconds) <= DETERMINISTIC_POLICY_LIMITS.DUPLICATE_WINDOW_SECONDS;

    if (!withinSameMinute) return false;

    const sameOrder = other.order_id === sanitizedTx.order_id;
    const sameIdentityAndValue =
      other.cpf_correlation_hash === sanitizedTx.cpf_correlation_hash &&
      Number(other.gross_amount_brl) === Number(sanitizedTx.gross_amount_brl) &&
      Number(other.refund_amount_brl) === Number(sanitizedTx.refund_amount_brl);

    return sameOrder || sameIdentityAndValue;
  });

  if (sameMinuteDuplicates.length > 0) {
    const dupIds = sameMinuteDuplicates.map((d) => d.transaction_id).join(', ');
    triggeredRules.push({
      code: 'RULE_SAME_MINUTE_DUPLICATE',
      severity: 'CRITICAL',
      description: `Duplicidade detectada na mesma janela de minuto (${txMinute}) com transação(ões) [${dupIds}] para o pedido ${sanitizedTx.order_id}.`,
    });
    deterministicScoreFloor = Math.max(deterministicScoreFloor, 88.5);
    suggestedClassification = ANOMALY_CLASSIFICATIONS.SUSPICIOUS_REFUND_DUPLICATION;
    suggestedAction = RECOMMENDED_ACTIONS.AUTOMATIC_BLOCK;
  }

  // =========================================================================
  // REGRA 2: LIMITES RÍGIDOS DE VALOR DE REEMBOLSO / ESTORNO
  // =========================================================================
  if (sanitizedTx.transaction_type === TRANSACTION_TYPES.REFUND_REQUEST) {
    const refundAmt = Number(sanitizedTx.refund_amount_brl || 0);
    const grossAmt = Number(sanitizedTx.gross_amount_brl || 0);

    // 2.a) Reembolso superior ao valor original do pedido (Over-refund Exploit)
    if (refundAmt > grossAmt) {
      triggeredRules.push({
        code: 'RULE_REFUND_EXCEEDS_ORIGINAL_ORDER',
        severity: 'CRITICAL',
        description: `Valor de reembolso solicitado (R$ ${refundAmt.toFixed(2)}) excede o valor bruto original do pedido (R$ ${grossAmt.toFixed(2)}) em +${(((refundAmt - grossAmt) / grossAmt) * 100).toFixed(1)}%.`,
      });
      deterministicScoreFloor = Math.max(deterministicScoreFloor, 97.5);
      suggestedClassification = ANOMALY_CLASSIFICATIONS.CRITICAL_FRAUD;
      suggestedAction = RECOMMENDED_ACTIONS.AUTOMATIC_BLOCK;
    }

    // 2.b) Violação do Teto Rígido de Reembolso (Hard Cap = R$ 350,00)
    if (refundAmt > DETERMINISTIC_POLICY_LIMITS.HARD_REFUND_LIMIT_BRL) {
      triggeredRules.push({
        code: 'RULE_HARD_REFUND_LIMIT_EXCEEDED',
        severity: 'CRITICAL',
        description: `Estorno de R$ ${refundAmt.toFixed(2)} ultrapassa o limite rígido de política financeira (Hard Cap de R$ ${DETERMINISTIC_POLICY_LIMITS.HARD_REFUND_LIMIT_BRL.toFixed(2)}).`,
      });
      deterministicScoreFloor = Math.max(deterministicScoreFloor, 91.0);
      if (suggestedClassification === ANOMALY_CLASSIFICATIONS.NORMAL) {
        suggestedClassification = ANOMALY_CLASSIFICATIONS.CRITICAL_FRAUD;
      }
      suggestedAction = RECOMMENDED_ACTIONS.AUTOMATIC_BLOCK;
    } else if (refundAmt > DETERMINISTIC_POLICY_LIMITS.SOFT_REFUND_LIMIT_BRL) {
      triggeredRules.push({
        code: 'RULE_SOFT_REFUND_AUDIT_THRESHOLD',
        severity: 'MEDIUM',
        description: `Estorno de R$ ${refundAmt.toFixed(2)} acima da alçada automática (Soft Limit de R$ ${DETERMINISTIC_POLICY_LIMITS.SOFT_REFUND_LIMIT_BRL.toFixed(2)}).`,
      });
      deterministicScoreFloor = Math.max(deterministicScoreFloor, 62.0);
      if (suggestedAction === RECOMMENDED_ACTIONS.APPROVE) {
        suggestedAction = RECOMMENDED_ACTIONS.HOLD_FOR_AUDIT;
      }
    }

    // 2.c) Velocidade de estornos recorrentes nos últimos 30 dias + OTP confirmado
    if (
      Number(sanitizedTx.prior_refund_count_30d) >= 4 &&
      sanitizedTx.delivery_status === 'DELIVERED_OTP_VERIFIED'
    ) {
      triggeredRules.push({
        code: 'RULE_HIGH_REFUND_VELOCITY_WITH_OTP',
        severity: 'HIGH',
        description: `Titular possui ${sanitizedTx.prior_refund_count_30d} estornos nos últimos 30 dias e contesta pedido entregue mediante validação de código OTP.`,
      });
      deterministicScoreFloor = Math.max(deterministicScoreFloor, 89.0);
      if (suggestedClassification === ANOMALY_CLASSIFICATIONS.NORMAL) {
        suggestedClassification = ANOMALY_CLASSIFICATIONS.CRITICAL_FRAUD;
      }
      suggestedAction = RECOMMENDED_ACTIONS.AUTOMATIC_BLOCK;
    }
  }

  // =========================================================================
  // REGRA 3: DETECÇÃO DE ABUSO DE CUPONS & STACKING / SYBIL FARMING
  // =========================================================================
  if (sanitizedTx.coupon_code) {
    const grossAmt = Number(sanitizedTx.gross_amount_brl || 0);
    const discountAmt = Number(sanitizedTx.coupon_discount_brl || 0);
    const discountRatio = grossAmt > 0 ? discountAmt / grossAmt : 0;

    if (discountRatio > DETERMINISTIC_POLICY_LIMITS.MAX_COUPON_DISCOUNT_RATIO) {
      triggeredRules.push({
        code: 'RULE_EXCESSIVE_COUPON_DISCOUNT',
        severity: 'HIGH',
        description: `Cupom "${sanitizedTx.coupon_code}" aplicou ${(discountRatio * 100).toFixed(1)}% de desconto (R$ ${discountAmt.toFixed(2)} sobre R$ ${grossAmt.toFixed(2)}), violando o teto de ${(DETERMINISTIC_POLICY_LIMITS.MAX_COUPON_DISCOUNT_RATIO * 100).toFixed(0)}%.`,
      });
      deterministicScoreFloor = Math.max(deterministicScoreFloor, 84.0);
      if (suggestedClassification === ANOMALY_CLASSIFICATIONS.NORMAL) {
        suggestedClassification = ANOMALY_CLASSIFICATIONS.COUPON_ABUSE;
      }
      if (suggestedAction === RECOMMENDED_ACTIONS.APPROVE) {
        suggestedAction =
          discountRatio >= 0.8
            ? RECOMMENDED_ACTIONS.AUTOMATIC_BLOCK
            : RECOMMENDED_ACTIONS.HOLD_FOR_AUDIT;
      }
    }

    if (sanitizedTx.coupon_single_use) {
      const couponCollisions = batchContext.filter(
        (other) =>
          other.transaction_id !== sanitizedTx.transaction_id &&
          other.coupon_code === sanitizedTx.coupon_code &&
          (other.device_fingerprint === sanitizedTx.device_fingerprint ||
            other.ip_address === sanitizedTx.ip_address ||
            other.card_correlation_hash === sanitizedTx.card_correlation_hash)
      );

      if (couponCollisions.length > 0) {
        const collisionIds = couponCollisions.map((c) => c.transaction_id).join(', ');
        triggeredRules.push({
          code: 'RULE_SINGLE_USE_COUPON_SYBIL_REPLAY',
          severity: 'CRITICAL',
          description: `Reutilização fraudulenta de cupom de uso único "${sanitizedTx.coupon_code}" no mesmo device/IP/cartão (${sanitizedTx.device_fingerprint}) com [${collisionIds}].`,
        });
        deterministicScoreFloor = Math.max(deterministicScoreFloor, 92.0);
        suggestedClassification = ANOMALY_CLASSIFICATIONS.COUPON_ABUSE;
        suggestedAction = RECOMMENDED_ACTIONS.AUTOMATIC_BLOCK;
      }
    }
  }

  // =========================================================================
  // REGRA 4: CONCILIAÇÃO DE REPASSE A RESTAURANTES (MERCHANT PAYOUT SPLIT)
  // =========================================================================
  if (sanitizedTx.transaction_type === TRANSACTION_TYPES.MERCHANT_PAYOUT) {
    const grossAmt = Number(sanitizedTx.gross_amount_brl || 0);
    const netAmt = Number(sanitizedTx.net_settlement_brl || 0);
    const retainedFeeRatio = grossAmt > 0 ? (grossAmt - netAmt) / grossAmt : 0;

    if (netAmt > grossAmt) {
      triggeredRules.push({
        code: 'RULE_PAYOUT_EXCEEDS_GROSS_GMV',
        severity: 'CRITICAL',
        description: `Repasse líquido ao restaurante (R$ ${netAmt.toFixed(2)}) é superior ao GMV bruto transacionado (R$ ${grossAmt.toFixed(2)}). Anomalia crítica de split.`,
      });
      deterministicScoreFloor = Math.max(deterministicScoreFloor, 95.0);
      suggestedClassification = ANOMALY_CLASSIFICATIONS.MERCHANT_DISCREPANCY;
      suggestedAction = RECOMMENDED_ACTIONS.AUTOMATIC_BLOCK;
    } else if (retainedFeeRatio < DETERMINISTIC_POLICY_LIMITS.MIN_PLATFORM_COMMISSION_RATIO) {
      triggeredRules.push({
        code: 'RULE_MERCHANT_COMMISSION_UNDERFLOW',
        severity: 'HIGH',
        description: `Taxa de intermediação retida (${(retainedFeeRatio * 100).toFixed(1)}%) abaixo do piso contratual mínimo de ${(DETERMINISTIC_POLICY_LIMITS.MIN_PLATFORM_COMMISSION_RATIO * 100).toFixed(0)}% para o restaurante ${sanitizedTx.merchant_name}.`,
      });
      deterministicScoreFloor = Math.max(deterministicScoreFloor, 76.5);
      suggestedClassification = ANOMALY_CLASSIFICATIONS.MERCHANT_DISCREPANCY;
      suggestedAction = RECOMMENDED_ACTIONS.HOLD_FOR_AUDIT;
    }
  }

  return {
    passedAllRules: triggeredRules.length === 0,
    deterministicScoreFloor,
    triggeredRules,
    suggestedClassification,
    suggestedAction,
  };
}
