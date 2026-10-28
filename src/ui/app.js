/**
 * @fileoverview Controlador Principal da Interface de Engenharia (UI Layer — FinGuard AI).
 * Conecta o Painel de Carga de Lote & PII Masking, o Dashboard de Compliance & Métricas
 * e a Tabela de Auditoria de Transações (`tb_finops_audit_logs`).
 */

import { INITIAL_BATCH_TRANSACTIONS } from '../domain/mockTransactions.js';
import {
  ANOMALY_CLASSIFICATIONS,
  FINGUARD_AUDIT_JSON_SCHEMA,
  FINGUARD_SYSTEM_INSTRUCTION,
  TRANSACTION_TYPES,
} from '../domain/models.js';
import {
  computeFinOpsMetrics,
  preprocessAndMaskBatch,
  runFinGuardBatchPipeline,
} from '../services/finopsPipelineService.js';
import { GEMINI_MODEL_ID } from '../services/geminiFraudService.js';
import {
  clearAuditLogRecords,
  formatRecordAsSqlInsert,
  listAuditLogRecords,
  TB_FINOPS_AUDIT_LOGS_DDL,
} from '../storage/auditRepository.js';
import {
  escapeHtml,
  formatBrl,
  renderActionBadge,
  renderAuditTableRows,
  renderClassificationBadge,
  renderClassificationBreakdown,
  renderInspectionModalContent,
  renderKpiCards,
  renderPiiComparisonPanel,
} from './components.js';

const appState = {
  rawTransactions: [...INITIAL_BATCH_TRANSACTIONS],
  maskedBatch: [],
  auditRecords: [],
  selectedTxIdForPii: INITIAL_BATCH_TRANSACTIONS[0].transaction_id,
  activeTab: 'ALL', // 'ALL' | 'BATCH_PII' | 'COMPLIANCE' | 'AUDIT_TABLE' | 'SCHEMA_SQL'
  tableFilter: 'ALL', // 'ALL' | 'ANOMALIES' | 'BLOCKED' | 'REFUND_DUP' | 'COUPON' | 'MERCHANT'
  searchQuery: '',
  apiKey: '',
  simulateRetryOnFirst: true,
  isProcessing: false,
  retryEventsLog: [],
};

/**
 * Inicializa a aplicação ao carregar o DOM.
 */
async function initFinGuardApp() {
  // Pré-processa o PII Masking imediatamente para exibição instantânea
  appState.maskedBatch = preprocessAndMaskBatch(appState.rawTransactions);

  // Renderiza o contrato JSON Schema e DDL SQL na aba de Arquitetura
  const schemaPre = document.getElementById('schema-json-viewer');
  if (schemaPre) {
    schemaPre.textContent = JSON.stringify(FINGUARD_AUDIT_JSON_SCHEMA, null, 2);
  }
  const sysPromptPre = document.getElementById('system-instruction-viewer');
  if (sysPromptPre) {
    sysPromptPre.textContent = FINGUARD_SYSTEM_INSTRUCTION;
  }

  bindEventListeners();
  renderPiiSelectorAndDiff();

  // Verifica se já existem logs persistidos no IndexedDB/LocalStorage; caso contrário, executa o lote inicial
  const existingLogs = await listAuditLogRecords();
  if (existingLogs && existingLogs.length >= appState.rawTransactions.length) {
    appState.auditRecords = existingLogs;
    updatePipelineStatus('Lote de 15 transações restaurado de tb_finops_audit_logs (IndexedDB + LocalStorage)', true);
    refreshAllViews();
  } else {
    await executeFullBatchAudit();
  }
}

/**
 * Executa o pipeline completo de conciliação financeira, PII Masking e inferência Gemini.
 */
async function executeFullBatchAudit() {
  if (appState.isProcessing) return;
  appState.isProcessing = true;
  appState.retryEventsLog = [];

  const runBtn = document.getElementById('btn-run-batch');
  if (runBtn) {
    runBtn.disabled = true;
    runBtn.textContent = '⏳ Processando Lote & Inferência IA...';
  }

  const keyInput = document.getElementById('gemini-api-key-input');
  appState.apiKey = keyInput ? keyInput.value.trim() : '';

  const engineBadge = document.getElementById('engine-mode-pill');
  if (engineBadge) {
    engineBadge.innerHTML = `<span class="status-dot"></span> ${
      appState.apiKey
        ? `Gemini Live (${GEMINI_MODEL_ID})`
        : `Gemini Structured Twin (${GEMINI_MODEL_ID})`
    }`;
  }

  try {
    updatePipelineStatus('Executando PII Masking (LGPD) e Regras Determinísticas...', false);

    const { records, maskedBatch } = await runFinGuardBatchPipeline(appState.rawTransactions, {
      apiKey: appState.apiKey,
      simulateRetryOnFirst: appState.simulateRetryOnFirst,
      onRetryEvent: (evt) => {
        appState.retryEventsLog.push(evt);
        renderRetryTelemetryBanner();
      },
      onProgress: ({ index, total, record }) => {
        updatePipelineStatus(
          `Auditando [${index}/${total}] ${record.transaction_id} → Score: ${record.fraud_score} (${record.anomaly_classification})`,
          index === total
        );
        appState.auditRecords = [
          ...appState.auditRecords.filter((r) => r.transaction_id !== record.transaction_id),
          record,
        ].sort((a, b) => a.transaction_id.localeCompare(b.transaction_id));
        refreshAllViews();
      },
    });

    appState.maskedBatch = maskedBatch;
    appState.auditRecords = records;
    updatePipelineStatus(
      `Pipeline Concluído: ${records.length} transações sanitizadas, auditadas e gravadas em tb_finops_audit_logs.`,
      true
    );
    refreshAllViews();
  } catch (err) {
    updatePipelineStatus(`Erro no processamento do lote: ${err.message}`, false);
  } finally {
    appState.isProcessing = false;
    if (runBtn) {
      runBtn.disabled = false;
      runBtn.textContent = '⚡ Carregar & Processar Lote (15 Transações)';
    }
  }
}

/**
 * Atualiza a barra de status do pipeline.
 */
function updatePipelineStatus(message, completed = false) {
  const statusEl = document.getElementById('pipeline-status-text');
  if (statusEl) {
    statusEl.textContent = message;
    statusEl.style.color = completed ? 'var(--fin-green)' : 'var(--ai-blue)';
  }
}

/**
 * Renderiza o banner de telemetria do Retry Pattern (Exponential Backoff).
 */
function renderRetryTelemetryBanner() {
  const container = document.getElementById('retry-telemetry-box');
  if (!container) return;

  if (appState.retryEventsLog.length === 0) {
    container.innerHTML = `<span style="color:var(--text-secondary);">Nenhuma falha transiente registrada no último ciclo (0 retries).</span>`;
    return;
  }

  container.innerHTML = appState.retryEventsLog
    .map(
      (evt) => `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 10px;background:rgba(210,153,34,0.12);border:1px solid var(--audit-amber-border);border-radius:6px;font-family:var(--font-mono);font-size:11.5px;color:var(--audit-amber-bright);margin-top:4px;">
        <span>↻ [RETRY_BACKOFF] Tx <strong>${escapeHtml(evt.transaction_id)}</strong> (Tentativa #${evt.attempt} recuperada após ${evt.delayMs}ms)</span>
        <span>Motivo: ${escapeHtml(evt.error?.message || 'HTTP 429 Rate Limit')}</span>
      </div>
    `
    )
    .join('');
}

/**
 * Atualiza todos os painéis da UI (KPIs, PII Masking Workbench, Tabela de Auditoria e SQL Dump).
 */
function refreshAllViews() {
  const metrics = computeFinOpsMetrics(appState.auditRecords);

  // 1. Atualiza contadores nas abas
  const countPii = document.getElementById('tab-count-pii');
  if (countPii) countPii.textContent = String(appState.maskedBatch.length);

  const countAudit = document.getElementById('tab-count-audit');
  if (countAudit) countAudit.textContent = String(appState.auditRecords.length);

  const countAnomalies = document.getElementById('tab-count-anomalies');
  if (countAnomalies) countAnomalies.textContent = `${metrics.fraudRatePercent.toFixed(0)}% Fraude`;

  // 2. Renderiza KPI Cards
  const kpiContainer = document.getElementById('kpi-cards-container');
  if (kpiContainer) {
    kpiContainer.innerHTML = renderKpiCards(metrics);
  }

  // 3. Renderiza Distribuição de Classificações
  const distContainer = document.getElementById('classification-dist-container');
  if (distContainer) {
    distContainer.innerHTML = renderClassificationBreakdown(metrics);
  }

  // 4. Renderiza Painel de PII Masking
  renderPiiSelectorAndDiff();

  // 5. Renderiza Tabela de Auditoria filtrada
  renderFilteredAuditTable();

  // 6. Atualiza SQL Dump (`tb_finops_audit_logs`)
  const sqlDumpViewer = document.getElementById('sql-dump-viewer');
  if (sqlDumpViewer) {
    const inserts = appState.auditRecords
      .slice(0, 6)
      .map((r) => formatRecordAsSqlInsert(r))
      .join('\n\n');
    sqlDumpViewer.textContent = `${TB_FINOPS_AUDIT_LOGS_DDL}\n\n-- Amostra de registros persistidos (${appState.auditRecords.length} total):\n${inserts}`;
  }
}

/**
 * Renderiza a lista lateral de transações e o comparativo Antes vs. Depois do PII Masking.
 */
function renderPiiSelectorAndDiff() {
  const listEl = document.getElementById('pii-tx-selector-list');
  const diffEl = document.getElementById('pii-comparison-container');
  if (!listEl || !diffEl) return;

  listEl.innerHTML = appState.maskedBatch
    .map((item) => {
      const tx = item.rawTransaction;
      const isSelected = tx.transaction_id === appState.selectedTxIdForPii;
      const auditMatch = appState.auditRecords.find((r) => r.transaction_id === tx.transaction_id);

      return `
        <button type="button" class="tx-selector-item ${isSelected ? 'active' : ''}" data-select-pii-tx="${escapeHtml(tx.transaction_id)}">
          <div class="tx-selector-top">
            <span>${escapeHtml(tx.transaction_id)}</span>
            <span>${formatBrl(tx.gross_amount_brl)}</span>
          </div>
          <div class="tx-selector-sub">
            <span>${escapeHtml(tx.merchant_name)}</span>
            <span>${auditMatch ? renderClassificationBadge(auditMatch.anomaly_classification) : '<span class="badge badge-blue">MASKED</span>'}</span>
          </div>
        </button>
      `;
    })
    .join('');

  const selectedItem =
    appState.maskedBatch.find(
      (item) => item.rawTransaction.transaction_id === appState.selectedTxIdForPii
    ) || appState.maskedBatch[0];

  diffEl.innerHTML = renderPiiComparisonPanel(selectedItem);
}

/**
 * Filtra e renderiza as linhas da Tabela de Auditoria de Transações.
 */
function renderFilteredAuditTable() {
  const tbody = document.getElementById('audit-table-tbody');
  if (!tbody) return;

  const filtered = appState.auditRecords.filter((row) => {
    if (appState.tableFilter === 'ANOMALIES' && row.anomaly_classification === ANOMALY_CLASSIFICATIONS.NORMAL) {
      return false;
    }
    if (appState.tableFilter === 'BLOCKED' && row.recommended_action !== 'AUTOMATIC_BLOCK') {
      return false;
    }
    if (
      appState.tableFilter === 'REFUND_DUP' &&
      row.anomaly_classification !== ANOMALY_CLASSIFICATIONS.SUSPICIOUS_REFUND_DUPLICATION
    ) {
      return false;
    }
    if (
      appState.tableFilter === 'COUPON' &&
      row.anomaly_classification !== ANOMALY_CLASSIFICATIONS.COUPON_ABUSE
    ) {
      return false;
    }
    if (
      appState.tableFilter === 'MERCHANT' &&
      row.anomaly_classification !== ANOMALY_CLASSIFICATIONS.MERCHANT_DISCREPANCY
    ) {
      return false;
    }

    if (appState.searchQuery) {
      const q = appState.searchQuery.toLowerCase();
      const haystack = `${row.transaction_id} ${row.order_id} ${row.merchant_name} ${row.anomaly_classification} ${row.recommended_action} ${row.coupon_code || ''} ${row.masked_customer_cpf}`.toLowerCase();
      if (!haystack.includes(q)) return false;
    }

    return true;
  });

  tbody.innerHTML = renderAuditTableRows(filtered);
}

/**
 * Abre o modal `<dialog>` com o JSON de auditoria e o relatório de explicabilidade da IA.
 */
function openInspectionModal(transactionId) {
  const record = appState.auditRecords.find((r) => r.transaction_id === transactionId);
  if (!record) return;

  const dialog = document.getElementById('audit-inspection-modal');
  const titleEl = document.getElementById('modal-tx-title');
  const bodyEl = document.getElementById('modal-inspection-body');

  if (!dialog || !bodyEl) return;

  if (titleEl) {
    titleEl.textContent = `Inspeção de Auditoria Técnica — ${record.transaction_id} (${record.merchant_name})`;
  }

  bodyEl.innerHTML = renderInspectionModalContent(record);

  const copyBtn = document.getElementById('btn-copy-contract-json');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      navigator.clipboard?.writeText(JSON.stringify(record.audit_contract_json, null, 2));
      copyBtn.textContent = '✓ Copiado!';
      setTimeout(() => {
        copyBtn.textContent = 'Copiar JSON';
      }, 1500);
    });
  }

  if (typeof dialog.showModal === 'function') {
    dialog.showModal();
  } else {
    dialog.setAttribute('open', 'true');
  }
}

/**
 * Alterna a visibilidade das seções conforme a aba selecionada.
 */
function switchActiveTab(tabId) {
  appState.activeTab = tabId;
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });

  const secPii = document.getElementById('section-batch-pii');
  const secCompliance = document.getElementById('section-compliance-dashboard');
  const secAuditTable = document.getElementById('section-audit-table');
  const secSchemaSql = document.getElementById('section-schema-sql');

  if (tabId === 'ALL') {
    secPii.hidden = false;
    secCompliance.hidden = false;
    secAuditTable.hidden = false;
    secSchemaSql.hidden = false;
  } else {
    secPii.hidden = tabId !== 'BATCH_PII';
    secCompliance.hidden = tabId !== 'COMPLIANCE';
    secAuditTable.hidden = tabId !== 'AUDIT_TABLE';
    secSchemaSql.hidden = tabId !== 'SCHEMA_SQL';
  }
}

/**
 * Injeta uma nova transação de ataque simulado no lote e reexecuta a conciliação.
 */
async function injectSimulatedAttackTransaction(event) {
  event.preventDefault();
  const vectorSelect = document.getElementById('sim-attack-vector');
  const vector = vectorSelect ? vectorSelect.value : 'OVER_REFUND';
  const nextNum = 9001 + appState.rawTransactions.length;
  const txId = `TXN-2026-${nextNum}`;

  let newTx;
  if (vector === 'SAME_MINUTE_DUP') {
    newTx = {
      transaction_id: txId,
      order_id: 'ORD-88415',
      timestamp: '2026-10-28T18:04:55-03:00',
      transaction_type: TRANSACTION_TYPES.REFUND_REQUEST,
      merchant_id: 'MRC-204',
      merchant_name: 'Sushi Kyoto Express',
      gross_amount_brl: 142.0,
      net_settlement_brl: 0.0,
      refund_amount_brl: 142.0,
      coupon_code: null,
      coupon_discount_brl: 0.0,
      coupon_single_use: false,
      customer_name: 'Fernanda Oliveira Costa',
      customer_cpf: '419.830.651-12',
      customer_email: 'fernanda.costa@outlook.com.br',
      customer_phone: '(11) 99120-5581',
      payment_method: 'CREDIT_CARD',
      card_number: '5412 7500 8911 3349',
      device_fingerprint: 'dfp_77c4e910ab',
      ip_address: '189.40.92.101',
      prior_refund_count_30d: 4,
      delivery_status: 'DELIVERED_NO_PHOTO',
      customer_notes: 'Terceira requisição concorrente no mesmo minuto (18:04) pelo CPF 419.830.651-12.',
    };
  } else if (vector === 'COUPON_SYBIL') {
    newTx = {
      transaction_id: txId,
      order_id: `ORD-${88500 + appState.rawTransactions.length}`,
      timestamp: '2026-10-28T18:21:10-03:00',
      transaction_type: TRANSACTION_TYPES.ORDER_PAYMENT,
      merchant_id: 'MRC-309',
      merchant_name: 'Pizzaria Napoli D.O.C.',
      gross_amount_brl: 120.0,
      net_settlement_brl: 102.0,
      refund_amount_brl: 0.0,
      coupon_code: 'PRIMEIRACOMPRA80',
      coupon_discount_brl: 96.0,
      coupon_single_use: true,
      customer_name: 'Fake Account Sybil Bot',
      customer_cpf: '741.852.963-00',
      customer_email: 'sybil.bot99@proton.me',
      customer_phone: '(21) 97612-8890',
      payment_method: 'CREDIT_CARD',
      card_number: '4024 0071 9921 6012',
      device_fingerprint: 'dfp_sybil_farm_08',
      ip_address: '200.155.14.88',
      prior_refund_count_30d: 3,
      delivery_status: 'PENDING_FRAUD_CHECK',
      customer_notes: 'Ataque automatizado de stacking de cupom 80% no cartão 4024 0071 9921 6012.',
    };
  } else {
    newTx = {
      transaction_id: txId,
      order_id: `ORD-${88500 + appState.rawTransactions.length}`,
      timestamp: '2026-10-28T18:22:00-03:00',
      transaction_type: TRANSACTION_TYPES.REFUND_REQUEST,
      merchant_id: 'MRC-608',
      merchant_name: 'Adega & Empório Prime 24h',
      gross_amount_brl: 520.0,
      net_settlement_brl: 0.0,
      refund_amount_brl: 750.0,
      coupon_code: null,
      coupon_discount_brl: 0.0,
      coupon_single_use: false,
      customer_name: 'Alexandre Pires Camargo',
      customer_cpf: '852.963.741-19',
      customer_email: 'alexandre.camargo@gmail.com',
      customer_phone: '(11) 98877-6655',
      payment_method: 'CREDIT_CARD',
      card_number: '4916 7788 2211 9900',
      device_fingerprint: 'dfp_emulator_rooted_99',
      ip_address: '45.227.190.11',
      prior_refund_count_30d: 8,
      delivery_status: 'DELIVERED_OTP_VERIFIED',
      customer_notes: 'Payload malicioso solicitando R$ 750,00 de estorno para o CPF 852.963.741-19.',
    };
  }

  appState.rawTransactions.push(newTx);
  appState.selectedTxIdForPii = txId;
  await executeFullBatchAudit();
}

/**
 * Registra todos os listeners de interação da UI.
 */
function bindEventListeners() {
  // Botão principal de carga e processamento do lote
  document.getElementById('btn-run-batch')?.addEventListener('click', () => {
    executeFullBatchAudit();
  });

  // Botão para resetar ao lote original de 15 transações
  document.getElementById('btn-reset-batch')?.addEventListener('click', async () => {
    await clearAuditLogRecords();
    appState.rawTransactions = [...INITIAL_BATCH_TRANSACTIONS];
    appState.selectedTxIdForPii = INITIAL_BATCH_TRANSACTIONS[0].transaction_id;
    await executeFullBatchAudit();
  });

  // Checkbox de simulação de Retry 429
  document.getElementById('chk-simulate-retry')?.addEventListener('change', (e) => {
    appState.simulateRetryOnFirst = e.target.checked;
  });

  // Abas de navegação
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      switchActiveTab(btn.dataset.tab);
    });
  });

  // Seleção de transação no Painel de PII Masking
  document.getElementById('pii-tx-selector-list')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-select-pii-tx]');
    if (!btn) return;
    appState.selectedTxIdForPii = btn.getAttribute('data-select-pii-tx');
    renderPiiSelectorAndDiff();
  });

  // Filtros rápidos da Tabela de Auditoria
  document.querySelectorAll('[data-table-filter]').forEach((btn) => {
    btn.addEventListener('click', () => {
      appState.tableFilter = btn.getAttribute('data-table-filter');
      document.querySelectorAll('[data-table-filter]').forEach((b) => {
        b.classList.toggle('active', b === btn);
      });
      renderFilteredAuditTable();
    });
  });

  // Busca textual na Tabela de Auditoria
  document.getElementById('audit-search-input')?.addEventListener('input', (e) => {
    appState.searchQuery = e.target.value.trim();
    renderFilteredAuditTable();
  });

  // Clique no botão "Inspecionar JSON & IA" na tabela
  document.getElementById('audit-table-tbody')?.addEventListener('click', (e) => {
    const inspectBtn = e.target.closest('.btn-inspect-tx');
    if (!inspectBtn) return;
    const txId = inspectBtn.getAttribute('data-tx-id');
    openInspectionModal(txId);
  });

  // Fechar modal
  document.getElementById('btn-close-modal')?.addEventListener('click', () => {
    const dialog = document.getElementById('audit-inspection-modal');
    dialog?.close();
  });

  // Fechar modal clicando no backdrop
  document.getElementById('audit-inspection-modal')?.addEventListener('click', (e) => {
    const dialog = document.getElementById('audit-inspection-modal');
    if (e.target === dialog) {
      dialog.close();
    }
  });

  // Exportar JSON completo de auditoria
  document.getElementById('btn-export-json')?.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(appState.auditRecords, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tb_finops_audit_logs_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Injetar ataque simulado
  document
    .getElementById('form-inject-attack')
    ?.addEventListener('submit', injectSimulatedAttackTransaction);
}

document.addEventListener('DOMContentLoaded', initFinGuardApp);
