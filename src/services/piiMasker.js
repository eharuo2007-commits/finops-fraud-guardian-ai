/**
 * @fileoverview Camada de Ingestão & Sanitização (Security Layer — LGPD Art. 46 / PCI-DSS).
 * Implementa PII Data Masking determinístico e inspeção Zero-Leakage antes que qualquer
 * payload atravesse a fronteira de rede em direção à Google Gemini API.
 */

const CPF_REGEX_GLOBAL = /\b(\d{3})\.?(\d{3})\.?(\d{3})-?(\d{2})\b/g;
const CARD_PAN_REGEX_GLOBAL = /\b(?:\d{4}[\s-]?){3}(\d{4})\b/g;
const EMAIL_REGEX_GLOBAL = /\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g;
const PHONE_REGEX_GLOBAL = /(\(?\d{2}\)?\s?)(\d{4,5})-(\d{4})\b/g;

/**
 * Gera um hash determinístico curto (FNV-1a 32-bit hex) para permitir correlação
 * de reincidência (ex: mesmo titular ou mesmo cartão em múltiplas contas) sem expor o dado real.
 *
 * @param {string} rawValue
 * @param {string} prefix
 * @returns {string}
 */
export function computeCorrelationToken(rawValue, prefix = 'tok') {
  const clean = String(rawValue || '').replace(/\s+/g, '').toLowerCase();
  let hash = 0x811c9dc5;
  for (let i = 0; i < clean.length; i++) {
    hash ^= clean.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${prefix}_${hash.toString(16).padStart(8, '0')}`;
}

/**
 * Mascara um CPF no formato LGPD exigido: `***.456.789-**`
 * @param {string} rawCpf
 * @returns {string}
 */
export function maskCpf(rawCpf) {
  if (!rawCpf || typeof rawCpf !== 'string') return '***.***.***-**';
  const digits = rawCpf.replace(/\D/g, '');
  if (digits.length !== 11) {
    return '***.***.***-**';
  }
  return `***.${digits.slice(3, 6)}.${digits.slice(6, 9)}-**`;
}

/**
 * Mascara endereço de e-mail preservando apenas prefixo/sufixo mínimos de auditoria:
 * Ex: `carlos.mendonca88@gmail.com` -> `ca***88@gm***.com`
 * @param {string} rawEmail
 * @returns {string}
 */
export function maskEmail(rawEmail) {
  if (!rawEmail || typeof rawEmail !== 'string' || !rawEmail.includes('@')) {
    return '***@***.***';
  }
  const [localPart, domainPart] = rawEmail.trim().split('@');
  const localPrefix = localPart.slice(0, 2);
  const localSuffix = localPart.length > 4 ? localPart.slice(-2) : '';
  const maskedLocal = `${localPrefix}***${localSuffix}`;

  const domainPieces = domainPart.split('.');
  const domainName = domainPieces[0] || '';
  const tld = domainPieces.slice(1).join('.') || 'com';
  const maskedDomain = `${domainName.slice(0, 2)}***.${tld}`;

  return `${maskedLocal}@${maskedDomain}`;
}

/**
 * Mascara número de cartão de crédito/débito (PAN) segundo PCI-DSS:
 * Ex: `4532 8810 3392 7104` -> `**** **** **** 7104`
 * @param {string} rawCard
 * @returns {string}
 */
export function maskCardNumber(rawCard) {
  if (!rawCard || typeof rawCard !== 'string') return '**** **** **** ****';
  const digits = rawCard.replace(/\D/g, '');
  if (digits.length < 4) return '**** **** **** ****';
  const last4 = digits.slice(-4);
  return `**** **** **** ${last4}`;
}

/**
 * Mascara telefone celular/fixo mantendo DDD e últimos 4 dígitos:
 * Ex: `(11) 98741-2230` -> `(11) *****-2230`
 * @param {string} rawPhone
 * @returns {string}
 */
export function maskPhone(rawPhone) {
  if (!rawPhone || typeof rawPhone !== 'string') return '(**) *****-****';
  return rawPhone.replace(PHONE_REGEX_GLOBAL, '$1*****-$3');
}

/**
 * Mascara o nome completo mantendo apenas o primeiro nome e a inicial do segundo:
 * Ex: `Carlos Eduardo Mendonça` -> `Carlos E. ***`
 * @param {string} rawName
 * @returns {string}
 */
export function maskCustomerName(rawName) {
  if (!rawName || typeof rawName !== 'string') return 'Titular Anonimizado ***';
  const parts = rawName.trim().split(/\s+/);
  if (parts.length === 1) return `${parts[0].slice(0, 2)}***`;
  return `${parts[0]} ${parts[1][0]}. ***`;
}

/**
 * Sanitiza textos livres (como `customer_notes`) removendo CPFs, PANs de cartão,
 * e-mails e telefones embutidos no meio de frases.
 * @param {string} text
 * @returns {string}
 */
export function sanitizeFreeTextPII(text) {
  if (!text || typeof text !== 'string') return '';
  return text
    .replace(CPF_REGEX_GLOBAL, '***.$2.$3-**')
    .replace(CARD_PAN_REGEX_GLOBAL, '**** **** **** $1')
    .replace(EMAIL_REGEX_GLOBAL, (_, local, dom) => maskEmail(`${local}@${dom}`))
    .replace(PHONE_REGEX_GLOBAL, '$1*****-$3');
}

/**
 * Verifica que o payload sanitizado não contém nenhum CPF bruto, PAN de 16 dígitos
 * ou e-mail aberto antes de enviar para a inferência externa.
 *
 * @param {object} sanitizedPayload
 * @returns {{ safe: boolean, violations: string[] }}
 */
export function verifyZeroPIIExposure(sanitizedPayload) {
  const serialized = JSON.stringify(sanitizedPayload);
  const violations = [];

  if (/\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/.test(serialized) || /\b\d{11}\b/.test(serialized)) {
    violations.push('RAW_CPF_DETECTED');
  }
  if (/\b(?:\d{4}[\s-]){3}\d{4}\b/.test(serialized)) {
    violations.push('RAW_CARD_PAN_DETECTED');
  }
  // E-mail sem máscara '***'
  const emailMatches = serialized.match(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || [];
  for (const match of emailMatches) {
    if (!match.includes('***')) {
      violations.push(`UNMASKED_EMAIL_DETECTED:${match}`);
    }
  }

  return {
    safe: violations.length === 0,
    violations,
  };
}

/**
 * Executa o pipeline completo de PII Masking em uma transação bruta,
 * retornando o payload seguro para a IA, os tokens de correlação e o relatório de diff.
 *
 * @param {object} rawTx Transação original com dados sensíveis
 * @returns {{
 *   sanitizedTransaction: object,
 *   maskingDiff: Array<{ field: string, label: string, before: string, after: string, technique: string }>,
 *   securityAttestation: { safe: boolean, maskedFieldsCount: number, standard: string, timestamp: string }
 * }}
 */
export function maskTransactionPII(rawTx) {
  const maskedCpf = maskCpf(rawTx.customer_cpf);
  const maskedEmail = maskEmail(rawTx.customer_email);
  const maskedCard = maskCardNumber(rawTx.card_number);
  const maskedPhone = maskPhone(rawTx.customer_phone);
  const maskedName = maskCustomerName(rawTx.customer_name);
  const maskedNotes = sanitizeFreeTextPII(rawTx.customer_notes);

  const cpfCorrelationHash = computeCorrelationToken(rawTx.customer_cpf, 'id_cpf');
  const cardCorrelationHash = computeCorrelationToken(rawTx.card_number, 'id_pan');

  const sanitizedTransaction = {
    transaction_id: rawTx.transaction_id,
    order_id: rawTx.order_id,
    timestamp: rawTx.timestamp,
    transaction_type: rawTx.transaction_type,
    merchant_id: rawTx.merchant_id,
    merchant_name: rawTx.merchant_name,
    gross_amount_brl: rawTx.gross_amount_brl,
    net_settlement_brl: rawTx.net_settlement_brl,
    refund_amount_brl: rawTx.refund_amount_brl,
    coupon_code: rawTx.coupon_code,
    coupon_discount_brl: rawTx.coupon_discount_brl,
    coupon_single_use: rawTx.coupon_single_use,
    customer_name: maskedName,
    customer_cpf: maskedCpf,
    customer_email: maskedEmail,
    customer_phone: maskedPhone,
    payment_method: rawTx.payment_method,
    card_number: maskedCard,
    cpf_correlation_hash: cpfCorrelationHash,
    card_correlation_hash: cardCorrelationHash,
    device_fingerprint: rawTx.device_fingerprint,
    ip_address: rawTx.ip_address,
    prior_refund_count_30d: rawTx.prior_refund_count_30d,
    delivery_status: rawTx.delivery_status,
    customer_notes: maskedNotes,
  };

  const verification = verifyZeroPIIExposure(sanitizedTransaction);
  if (!verification.safe) {
    throw new Error(
      `[SECURITY_GATEWAY_BLOCK] Vazamento de PII impedido na transação ${rawTx.transaction_id}: ${verification.violations.join(', ')}`
    );
  }

  const maskingDiff = [
    {
      field: 'customer_cpf',
      label: 'CPF do Titular',
      before: rawTx.customer_cpf,
      after: maskedCpf,
      technique: 'Partial Redaction (***.456.789-**) + FNV1a Token',
    },
    {
      field: 'customer_email',
      label: 'E-mail de Cadastro',
      before: rawTx.customer_email,
      after: maskedEmail,
      technique: 'Local/Domain Pattern Masking (LGPD Art. 46)',
    },
    {
      field: 'card_number',
      label: 'PAN do Cartão',
      before: rawTx.card_number,
      after: maskedCard,
      technique: 'PCI-DSS Last-4 Truncation (**** **** **** NNNN)',
    },
    {
      field: 'customer_name',
      label: 'Nome do Cliente',
      before: rawTx.customer_name,
      after: maskedName,
      technique: 'Surname Pseudonymization',
    },
    {
      field: 'customer_phone',
      label: 'Telefone Contato',
      before: rawTx.customer_phone,
      after: maskedPhone,
      technique: 'Subscriber Prefix Masking',
    },
    {
      field: 'customer_notes',
      label: 'Observações / Logs',
      before: rawTx.customer_notes,
      after: maskedNotes,
      technique: 'Deep Regex Free-Text Sanitizer',
    },
  ];

  return {
    sanitizedTransaction,
    maskingDiff,
    securityAttestation: {
      safe: verification.safe,
      maskedFieldsCount: maskingDiff.length,
      standard: 'LGPD Art. 46 + PCI-DSS v4.0 Zero-Trust AI Gateway',
      timestamp: new Date().toISOString(),
    },
  };
}
