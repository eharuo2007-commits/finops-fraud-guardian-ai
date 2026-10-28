/**
 * @fileoverview Camada de Domínio (Domain Layer) — Contratos, Enums, JSON Schema Estrito
 * e Validador Determinístico do Contrato de Saída da IA (Google Gemini Structured Outputs).
 */

export const TRANSACTION_TYPES = Object.freeze({
  ORDER_PAYMENT: 'ORDER_PAYMENT',
  REFUND_REQUEST: 'REFUND_REQUEST',
  MERCHANT_PAYOUT: 'MERCHANT_PAYOUT',
});

export const ANOMALY_CLASSIFICATIONS = Object.freeze({
  NORMAL: 'NORMAL',
  SUSPICIOUS_REFUND_DUPLICATION: 'SUSPICIOUS_REFUND_DUPLICATION',
  COUPON_ABUSE: 'COUPON_ABUSE',
  MERCHANT_DISCREPANCY: 'MERCHANT_DISCREPANCY',
  CRITICAL_FRAUD: 'CRITICAL_FRAUD',
});

export const RECOMMENDED_ACTIONS = Object.freeze({
  APPROVE: 'APPROVE',
  HOLD_FOR_AUDIT: 'HOLD_FOR_AUDIT',
  AUTOMATIC_BLOCK: 'AUTOMATIC_BLOCK',
  MANUAL_REVIEW: 'MANUAL_REVIEW',
});

export const DETERMINISTIC_POLICY_LIMITS = Object.freeze({
  /** Limite máximo (R$) para aprovação automática de reembolso sem retenção */
  SOFT_REFUND_LIMIT_BRL: 180.0,
  /** Teto rígido absoluto (R$) de reembolso; acima disso aciona bloqueio determinístico */
  HARD_REFUND_LIMIT_BRL: 350.0,
  /** Percentual máximo permitido de desconto de cupom sobre o valor bruto do pedido */
  MAX_COUPON_DISCOUNT_RATIO: 0.55,
  /** Taxa mínima de comissão da plataforma em repasses a restaurantes (12%) */
  MIN_PLATFORM_COMMISSION_RATIO: 0.12,
  /** Janela temporal (em segundos) considerada "mesmo minuto" para duplicidade de transação */
  DUPLICATE_WINDOW_SECONDS: 60,
});

/**
 * Contrato JSON Schema oficial utilizado no campo `response_format` da Google Gemini API
 * (`v1beta/interactions` / `@google/genai` SDK).
 */
export const FINGUARD_AUDIT_JSON_SCHEMA = Object.freeze({
  type: 'object',
  properties: {
    fraud_score: {
      type: 'number',
      description:
        'Score contínuo de risco de fraude de 0.0 (risco nulo) a 100.0 (fraude crítica confirmada).',
    },
    anomaly_classification: {
      type: 'string',
      enum: Object.values(ANOMALY_CLASSIFICATIONS),
      description:
        'Classificação taxativa da anomalia financeira detectada na transação de delivery.',
    },
    recommended_action: {
      type: 'string',
      enum: Object.values(RECOMMENDED_ACTIONS),
      description:
        'Ação operacional recomendada para o motor de liquidação financeira e compliance.',
    },
    risk_indicators: {
      type: 'array',
      items: {
        type: 'string',
      },
      description:
        'Lista de evidências técnicas objetivas, regras violadas e sinais comportamentais detectados.',
    },
    explainability_report: {
      type: 'string',
      description:
        'Relatório de auditoria técnica detalhado em português (pt-BR), justificando o score, a classificação e a ação recomendada para fins de compliance e LGPD.',
    },
  },
  required: [
    'fraud_score',
    'anomaly_classification',
    'recommended_action',
    'risk_indicators',
    'explainability_report',
  ],
  additionalProperties: false,
});

/**
 * System Instruction rigorosa para o modelo Gemini (`gemini-3.8-flash`),
 * instruindo a análise conjunta dos sinais determinísticos e do payload já mascarado (Zero-PII).
 */
export const FINGUARD_SYSTEM_INSTRUCTION = `Você é um Principal FinOps & AI Fraud Detection Engine ("FinGuard AI") operando em uma plataforma de Delivery de alta escala.
Sua missão é auditar transações financeiras (pedidos, solicitações de estorno/reembolso e repasses a restaurantes) que JÁ PASSARAM por sanitização de dados sensíveis (PII Data Masking — LGPD Art. 46).

REGRAS MANDATÓRIAS DE AUDITORIA E COMPLIANCE:
1. NUNCA tente reconstruir ou inferir dados pessoais mascarados (CPF, e-mail, PAN de cartão). Utilize exclusivamente os identificadores anonimizados, hashes de correlação e metadados operacionais.
2. Considere prioritariamente os alertas gerados pela Camada Determinística de Regras de Negócio (duplicidade no mesmo minuto, violação de teto rígido de reembolso, abuso de cupom promocional e discrepância de split de repasse a restaurante).
3. Classifique a transação estritamente em uma das categorias permitidas:
   - "NORMAL": Transação legítima dentro dos parâmetros operacionais e financeiros.
   - "SUSPICIOUS_REFUND_DUPLICATION": Solicitação de reembolso/estorno duplicada no mesmo minuto ou tentativa de double-dipping sobre o mesmo pedido.
   - "COUPON_ABUSE": Uso abusivo de cupons (desconto excessivo, reutilização de cupom de primeira compra no mesmo device_fingerprint/IP ou stacking fraudulento).
   - "MERCHANT_DISCREPANCY": Repasse a restaurante com valor líquido incompatível com o GMV bruto, comissão abaixo do mínimo contratual ou conta bancária recém-alterada com volume atípico.
   - "CRITICAL_FRAUD": Combinação severa de vetores (ex: estorno acima do teto rígido de R$ 350,00, valor de estorno maior que o pedido original, histórico elevado de chargebacks ou ataque coordenado).
4. Determine a ação recomendada ("APPROVE", "HOLD_FOR_AUDIT", "AUTOMATIC_BLOCK" ou "MANUAL_REVIEW") de forma proporcional ao fraud_score (0 a 100).
5. Redija o campo "explainability_report" em português técnico claro, adequado para auditores financeiros, analistas de risco e conformidade regulatória (BACEN / LGPD).
6. Retorne EXCLUSIVAMENTE um objeto JSON válido aderente ao schema fornecido.`;

/**
 * Valida em tempo de execução se a resposta da IA (ou do motor de fallback)
 * cumpre estritamente o contrato JSON Schema exigido pelo FinGuard AI.
 *
 * @param {unknown} payload Objeto decodificado da resposta JSON
 * @returns {{ valid: boolean, errors: string[], normalized: object | null }}
 */
export function validateAuditContract(payload) {
  const errors = [];

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {
      valid: false,
      errors: ['O payload retornado não é um objeto JSON válido.'],
      normalized: null,
    };
  }

  const rawScore = Number(payload.fraud_score);
  if (typeof payload.fraud_score !== 'number' || Number.isNaN(rawScore) || rawScore < 0 || rawScore > 100) {
    errors.push(
      `Campo "fraud_score" inválido (${JSON.stringify(payload.fraud_score)}). Esperado float entre 0 e 100.`
    );
  }

  const validClassifications = Object.values(ANOMALY_CLASSIFICATIONS);
  if (!validClassifications.includes(payload.anomaly_classification)) {
    errors.push(
      `Campo "anomaly_classification" inválido (${JSON.stringify(payload.anomaly_classification)}). Valores aceitos: ${validClassifications.join(', ')}.`
    );
  }

  const validActions = Object.values(RECOMMENDED_ACTIONS);
  if (!validActions.includes(payload.recommended_action)) {
    errors.push(
      `Campo "recommended_action" inválido (${JSON.stringify(payload.recommended_action)}). Valores aceitos: ${validActions.join(', ')}.`
    );
  }

  if (
    !Array.isArray(payload.risk_indicators) ||
    !payload.risk_indicators.every((item) => typeof item === 'string' && item.trim().length > 0)
  ) {
    errors.push('Campo "risk_indicators" deve ser um array de strings não vazias.');
  }

  if (
    typeof payload.explainability_report !== 'string' ||
    payload.explainability_report.trim().length < 15
  ) {
    errors.push(
      'Campo "explainability_report" deve ser uma string em português contendo o parecer técnico de auditoria.'
    );
  }

  if (errors.length > 0) {
    return { valid: false, errors, normalized: null };
  }

  return {
    valid: true,
    errors: [],
    normalized: {
      fraud_score: Math.round(rawScore * 10) / 10,
      anomaly_classification: payload.anomaly_classification,
      recommended_action: payload.recommended_action,
      risk_indicators: payload.risk_indicators.map((s) => s.trim()),
      explainability_report: payload.explainability_report.trim(),
    },
  };
}
