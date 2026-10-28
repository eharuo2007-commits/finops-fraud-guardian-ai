/**
 * @fileoverview Componentes de Interface de Engenharia (UI Layer) — Renderizadores puros
 * para o Painel de Carga & PII Masking, Dashboard de Compliance e Tabela de Auditoria.
 */

import { ANOMALY_CLASSIFICATIONS, RECOMMENDED_ACTIONS } from '../domain/models.js';
import { formatRecordAsSqlInsert } from '../storage/auditRepository.js';

const brlFormatter = new Intl.NumberFormat('pt-BR', {
  style: 'currency',
  currency: 'BRL',
});

export function formatBrl(value) {
  return brlFormatter.format(Number(value || 0));
}

export function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function getScoreColor(score) {
  const s = Number(score || 0);
  if (s >= 75) return 'var(--fraud-red)';
  if (s >= 45) return 'var(--audit-amber-bright)';
  return 'var(--fin-green)';
}

export function renderClassificationBadge(classification) {
  switch (classification) {
    case ANOMALY_CLASSIFICATIONS.NORMAL:
      return `<span class="badge badge-normal">● NORMAL</span>`;
    case ANOMALY_CLASSIFICATIONS.SUSPICIOUS_REFUND_DUPLICATION:
      return `<span class="badge badge-critical">⚡ SUSPICIOUS_REFUND_DUPLICATION</span>`;
    case ANOMALY_CLASSIFICATIONS.COUPON_ABUSE:
      return `<span class="badge badge-purple">🎟 COUPON_ABUSE</span>`;
    case ANOMALY_CLASSIFICATIONS.MERCHANT_DISCREPANCY:
      return `<span class="badge badge-amber">⚖ MERCHANT_DISCREPANCY</span>`;
    case ANOMALY_CLASSIFICATIONS.CRITICAL_FRAUD:
      return `<span class="badge badge-critical">🚨 CRITICAL_FRAUD</span>`;
    default:
      return `<span class="badge badge-blue">${escapeHtml(classification)}</span>`;
  }
}

export function renderActionBadge(action) {
  switch (action) {
    case RECOMMENDED_ACTIONS.APPROVE:
      return `<span class="badge badge-approve">✓ APPROVE</span>`;
    case RECOMMENDED_ACTIONS.AUTOMATIC_BLOCK:
      return `<span class="badge badge-block">✕ AUTOMATIC_BLOCK</span>`;
    case RECOMMENDED_ACTIONS.HOLD_FOR_AUDIT:
      return `<span class="badge badge-hold">⏸ HOLD_FOR_AUDIT</span>`;
    case RECOMMENDED_ACTIONS.MANUAL_REVIEW:
      return `<span class="badge badge-amber">👁 MANUAL_REVIEW</span>`;
    default:
      return `<span class="badge badge-blue">${escapeHtml(action)}</span>`;
  }
}

export function renderTransactionTypeTag(type) {
  const map = {
    ORDER_PAYMENT: { label: 'ORDER_PAYMENT', color: 'var(--ai-blue)' },
    REFUND_REQUEST: { label: 'REFUND_REQUEST', color: 'var(--fraud-red)' },
    MERCHANT_PAYOUT: { label: 'MERCHANT_PAYOUT', color: 'var(--audit-amber-bright)' },
  };
  const info = map[type] || { label: type, color: 'var(--text-secondary)' };
  return `<span style="font-family:var(--font-mono);font-size:11px;color:${info.color};font-weight:700;">${escapeHtml(info.label)}</span>`;
}

/**
 * Renderiza os 4 Cards Principais do Dashboard de Compliance & Métricas FinOps.
 */
export function renderKpiCards(metrics) {
  return `
    <div class="kpi-card accent-green">
      <div class="kpi-header">
        <span>Total Transacionado (GMV)</span>
        <span style="color:var(--fin-green)">BRL ●</span>
      </div>
      <div class="kpi-value green">${formatBrl(metrics.totalTransactedBrl)}</div>
      <div class="kpi-subtext">
        <span>Volume Protegido de Fraude:</span>
        <strong style="color:var(--fin-green);font-family:var(--font-mono)">${formatBrl(metrics.protectedAmountBrl)}</strong>
      </div>
    </div>

    <div class="kpi-card accent-blue">
      <div class="kpi-header">
        <span>Volume Analisado & PII Masking</span>
        <span style="color:var(--ai-blue)">LGPD ●</span>
      </div>
      <div class="kpi-value">${metrics.analyzedCount} <span style="font-size:15px;color:var(--text-secondary);font-weight:500;">txs</span></div>
      <div class="kpi-subtext">
        <span>Campos PII Sanitizados: <strong>${metrics.piiMaskedFieldsTotal}</strong></span>
        <span style="font-family:var(--font-mono)">~${metrics.avgLatencyMs}ms/tx</span>
      </div>
    </div>

    <div class="kpi-card accent-amber">
      <div class="kpi-header">
        <span>Taxa de Fraudes Detectadas</span>
        <span style="color:var(--audit-amber-bright)">ANOMALIAS ●</span>
      </div>
      <div class="kpi-value amber">${metrics.fraudRatePercent.toFixed(1)}%</div>
      <div class="kpi-subtext">
        <span><strong>${metrics.fraudDetectedCount}</strong> anômalas de ${metrics.analyzedCount} txs</span>
        <span style="font-family:var(--font-mono)">Score Médio: ${metrics.avgFraudScore}</span>
      </div>
    </div>

    <div class="kpi-card accent-red">
      <div class="kpi-header">
        <span>Transações Bloqueadas / Retidas</span>
        <span style="color:var(--fraud-red)">ENFORCEMENT ●</span>
      </div>
      <div class="kpi-value red">${metrics.blockedCount} <span style="font-size:14px;color:var(--audit-amber-bright)">(+${metrics.holdForAuditCount} Hold)</span></div>
      <div class="kpi-subtext">
        <span>Aprovadas: <strong style="color:var(--fin-green)">${metrics.approvedCount}</strong></span>
        <span style="font-family:var(--font-mono)">Retries IA: ${metrics.totalRetriesExecuted}</span>
      </div>
    </div>
  `;
}

/**
 * Renderiza a distribuição por classe de anomalia no Dashboard.
 */
export function renderClassificationBreakdown(metrics) {
  const total = Math.max(1, metrics.analyzedCount);
  const items = [
    {
      key: ANOMALY_CLASSIFICATIONS.NORMAL,
      label: 'NORMAL (Operação Legítima)',
      color: 'var(--fin-green)',
    },
    {
      key: ANOMALY_CLASSIFICATIONS.CRITICAL_FRAUD,
      label: 'CRITICAL_FRAUD (Violação Teto Rígido / Over-Refund)',
      color: 'var(--fraud-red)',
    },
    {
      key: ANOMALY_CLASSIFICATIONS.SUSPICIOUS_REFUND_DUPLICATION,
      label: 'SUSPICIOUS_REFUND_DUPLICATION (Mesmo Minuto)',
      color: '#ff7b72',
    },
    {
      key: ANOMALY_CLASSIFICATIONS.COUPON_ABUSE,
      label: 'COUPON_ABUSE (Sybil Replay / Desconto Abusivo)',
      color: 'var(--purple-coupon)',
    },
    {
      key: ANOMALY_CLASSIFICATIONS.MERCHANT_DISCREPANCY,
      label: 'MERCHANT_DISCREPANCY (Divergência de Split / Repasse)',
      color: 'var(--audit-amber-bright)',
    },
  ];

  return items
    .map((item) => {
      const count = metrics.byClassification[item.key] || 0;
      const pct = Math.round((count / total) * 100);
      return `
        <div class="dist-item">
          <div class="dist-meta">
            <span>${escapeHtml(item.label)}</span>
            <strong>${count} txs (${pct}%)</strong>
          </div>
          <div class="dist-bar-track">
            <div class="dist-bar-fill" style="width:${pct}%;background:${item.color};"></div>
          </div>
        </div>
      `;
    })
    .join('');
}

/**
 * Renderiza o comparador Side-by-Side de PII Masking (Antes vs. Depois) para uma transação do lote.
 */
export function renderPiiComparisonPanel(maskedItem) {
  if (!maskedItem) {
    return `<div style="color:var(--text-secondary);padding:20px;">Selecione uma transação à esquerda para inspecionar a sanitização PII em tempo real.</div>`;
  }

  const { rawTransaction, sanitizedTransaction, maskingDiff, securityAttestation } = maskedItem;

  const beforeRows = maskingDiff
    .map(
      (d) => `
      <div class="pii-field-row">
        <div class="pii-field-label">
          <span>${escapeHtml(d.label)} (<code>${escapeHtml(d.field)}</code>)</span>
          <span style="color:var(--fraud-red)">EXPOSED PII</span>
        </div>
        <div class="pii-field-val exposed">${escapeHtml(d.before)}</div>
      </div>
    `
    )
    .join('');

  const afterRows = maskingDiff
    .map(
      (d) => `
      <div class="pii-field-row">
        <div class="pii-field-label">
          <span>${escapeHtml(d.label)} (<code>${escapeHtml(d.field)}</code>)</span>
          <span style="color:var(--fin-green)">${escapeHtml(d.technique)}</span>
        </div>
        <div class="pii-field-val redacted">${escapeHtml(d.after)}</div>
      </div>
    `
    )
    .join('');

  return `
    <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px;">
      <div>
        <span class="mono-id" style="font-size:15px;">${escapeHtml(rawTransaction.transaction_id)}</span>
        <span style="color:var(--text-secondary);margin-left:8px;">Pedido <code>${escapeHtml(rawTransaction.order_id)}</code> — ${escapeHtml(rawTransaction.merchant_name)}</span>
      </div>
      <span class="badge badge-normal">
        🛡 ZERO RAW PII LEAKAGE • ${securityAttestation.maskedFieldsCount} CAMPOS SANITIZADOS
      </span>
    </div>

    <div class="pii-diff-grid">
      <div class="pii-box raw-danger">
        <div class="pii-box-header" style="color:var(--fraud-red);">
          <span>⚠ ANTES (RAW INGESTION PAYLOAD — SENSÍVEL)</span>
          <span>BLOQUEADO PARA IA</span>
        </div>
        ${beforeRows}
      </div>

      <div class="pii-box masked-safe">
        <div class="pii-box-header" style="color:var(--fin-green);">
          <span>🔒 DEPOIS (PII MASKED PAYLOAD — LGPD COMPLIANT)</span>
          <span>ENVIADO À GEMINI API</span>
        </div>
        ${afterRows}
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
      <div>
        <div style="font-size:11.5px;color:var(--text-secondary);margin-bottom:6px;font-family:var(--font-mono);">
          TOKENS DETERMINÍSTICOS DE CORRELAÇÃO (ANTI-SYBIL SEM EXPOR PII):
        </div>
        <div class="code-block" style="color:var(--ai-blue);padding:10px;">cpf_correlation_hash:  "${escapeHtml(sanitizedTransaction.cpf_correlation_hash)}"
card_correlation_hash: "${escapeHtml(sanitizedTransaction.card_correlation_hash)}"
device_fingerprint:    "${escapeHtml(sanitizedTransaction.device_fingerprint)}"</div>
      </div>
      <div>
        <div style="font-size:11.5px;color:var(--text-secondary);margin-bottom:6px;font-family:var(--font-mono);">
          PAYLOAD JSON SANITIZADO ENVIADO PARA INFERÊNCIA:
        </div>
        <pre class="code-block" style="max-height:110px;padding:10px;color:var(--fin-green);">${escapeHtml(JSON.stringify(sanitizedTransaction, null, 2))}</pre>
      </div>
    </div>
  `;
}

/**
 * Renderiza as linhas da Tabela de Auditoria de Transações (`tb_finops_audit_logs`).
 */
export function renderAuditTableRows(records) {
  if (!records || records.length === 0) {
    return `
      <tr>
        <td colspan="8" style="text-align:center;padding:32px;color:var(--text-secondary);">
          Nenhuma transação encontrada para os filtros selecionados.
        </td>
      </tr>
    `;
  }

  return records
    .map((row) => {
      const scoreColor = getScoreColor(row.fraud_score);
      const isCritical = row.fraud_score >= 75;
      const rulesCount = Array.isArray(row.deterministic_rules)
        ? row.deterministic_rules.length
        : 0;
      const timeShort = String(row.timestamp || '').slice(11, 19);

      return `
        <tr class="${isCritical ? 'row-critical' : ''}" data-tx-id="${escapeHtml(row.transaction_id)}">
          <td>
            <div class="mono-id">${escapeHtml(row.transaction_id)}</div>
            <div class="mono-sub">${escapeHtml(row.order_id)} • ${escapeHtml(timeShort)}</div>
          </td>
          <td>
            <div>${renderTransactionTypeTag(row.transaction_type)}</div>
            <div style="font-weight:600;margin-top:2px;">${escapeHtml(row.merchant_name)}</div>
          </td>
          <td>
            <div style="font-family:var(--font-mono);font-weight:700;">
              Bruto: ${formatBrl(row.gross_amount_brl)}
            </div>
            ${
              row.refund_amount_brl > 0
                ? `<div style="font-family:var(--font-mono);font-size:11.5px;color:var(--fraud-red);">Estorno: ${formatBrl(row.refund_amount_brl)}</div>`
                : ''
            }
            ${
              row.coupon_code
                ? `<div style="font-family:var(--font-mono);font-size:11.5px;color:var(--purple-coupon);">Cupom ${escapeHtml(row.coupon_code)}: -${formatBrl(row.coupon_discount_brl)}</div>`
                : ''
            }
            ${
              row.transaction_type === 'MERCHANT_PAYOUT'
                ? `<div style="font-family:var(--font-mono);font-size:11.5px;color:var(--audit-amber-bright);">Líquido: ${formatBrl(row.net_settlement_brl)}</div>`
                : ''
            }
          </td>
          <td>
            <div style="font-family:var(--font-mono);font-size:12px;color:var(--fin-green);">
              CPF: ${escapeHtml(row.masked_customer_cpf)}
            </div>
            <div class="mono-sub">Card: ${escapeHtml(row.masked_card_pan)}</div>
            <div class="mono-sub">${escapeHtml(row.masked_customer_email)}</div>
          </td>
          <td class="score-cell">
            <div class="score-header">
              <span style="color:${scoreColor}">${Number(row.fraud_score).toFixed(1)}</span>
              <span style="color:var(--text-muted);font-size:11px;">/ 100</span>
            </div>
            <div class="score-bar">
              <div class="score-fill" style="width:${Math.min(100, row.fraud_score)}%;background:${scoreColor};"></div>
            </div>
            <div class="mono-sub" style="margin-top:4px;">
              ${
                rulesCount > 0
                  ? `<span style="color:var(--fraud-red)">${rulesCount} regra(s) violada(s)</span>`
                  : `<span style="color:var(--fin-green)">Regras OK</span>`
              }
            </div>
          </td>
          <td>${renderClassificationBadge(row.anomaly_classification)}</td>
          <td>${renderActionBadge(row.recommended_action)}</td>
          <td>
            <button class="btn btn-blue btn-inspect-tx" data-tx-id="${escapeHtml(row.transaction_id)}" style="padding:6px 11px;font-size:12px;">
              🔍 Inspecionar JSON & IA
            </button>
          </td>
        </tr>
      `;
    })
    .join('');
}

/**
 * Renderiza o conteúdo interno do Modal de Inspeção de Auditoria e Explicabilidade da IA.
 */
export function renderInspectionModalContent(record) {
  if (!record) return '';
  const isHighRisk = record.fraud_score >= 65;
  const scoreColor = getScoreColor(record.fraud_score);
  const sqlInsert = formatRecordAsSqlInsert(record);

  const indicatorsHtml = (record.risk_indicators || [])
    .map(
      (ind) => `
      <li class="indicator-item">
        <span style="color:${isHighRisk ? 'var(--fraud-red)' : 'var(--fin-green)'}">▸</span>
        <span>${escapeHtml(ind)}</span>
      </li>
    `
    )
    .join('');

  const piiDiffMini = (record.masking_diff || [])
    .map(
      (d) => `
      <tr>
        <td style="font-family:var(--font-mono);font-size:12px;">${escapeHtml(d.field)}</td>
        <td style="font-family:var(--font-mono);font-size:12px;color:var(--fraud-red);">${escapeHtml(d.before)}</td>
        <td style="font-family:var(--font-mono);font-size:12px;color:var(--fin-green);">${escapeHtml(d.after)}</td>
      </tr>
    `
    )
    .join('');

  return `
    <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px;">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
        ${renderClassificationBadge(record.anomaly_classification)}
        ${renderActionBadge(record.recommended_action)}
        <span class="badge badge-blue">Score: <strong style="color:${scoreColor}">${Number(record.fraud_score).toFixed(1)}/100</strong></span>
      </div>
      <div class="mono-sub">
        Log ID: <code>${escapeHtml(record.audit_log_id)}</code> • Latência: <code>${record.inference_latency_ms}ms</code> • Tentativas: <code>${record.retry_attempts}</code>
      </div>
    </div>

    <div class="explainability-box ${isHighRisk ? 'danger' : 'safe'}">
      <div style="font-size:11.5px;font-family:var(--font-mono);font-weight:700;text-transform:uppercase;margin-bottom:6px;color:${isHighRisk ? 'var(--fraud-red)' : 'var(--fin-green)'};">
        🧠 Relatório de Explicabilidade Técnica da IA (explainability_report — pt-BR)
      </div>
      <p style="font-size:13.5px;line-height:1.6;color:var(--text-primary);">
        ${escapeHtml(record.explainability_report)}
      </p>
    </div>

    <div>
      <div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text-secondary);margin-bottom:8px;">
        Evidências Técnicas & Indicadores de Risco (risk_indicators)
      </div>
      <ul class="indicator-list">
        ${indicatorsHtml}
      </ul>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">
      <div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
          <span style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text-secondary);">
            Contrato JSON Estrito (Google Gemini Structured Output)
          </span>
          <button class="btn" id="btn-copy-contract-json" style="padding:3px 8px;font-size:11px;">Copiar JSON</button>
        </div>
        <pre class="code-block" id="modal-contract-json">${escapeHtml(JSON.stringify(record.audit_contract_json, null, 2))}</pre>
      </div>

      <div>
        <div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text-secondary);margin-bottom:6px;">
          Evidência de Sanitização PII (LGPD — Antes vs. Depois)
        </div>
        <div class="table-responsive">
          <table class="audit-table" style="font-size:12px;">
            <thead>
              <tr>
                <th>Campo</th>
                <th>Original (Bloqueado)</th>
                <th>Mascarado (Enviado à IA)</th>
              </tr>
            </thead>
            <tbody>
              ${piiDiffMini}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div>
      <div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text-secondary);margin-bottom:6px;">
        Persistência SQL Equivalente (Tabela: tb_finops_audit_logs)
      </div>
      <pre class="code-block" style="color:var(--text-secondary);font-size:11.5px;max-height:140px;">${escapeHtml(sqlInsert)}</pre>
    </div>
  `;
}
