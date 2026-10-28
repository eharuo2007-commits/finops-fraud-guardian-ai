/**
 * @fileoverview Utilitário de Resiliência Backend — Retry Pattern com Exponential Backoff + Full Jitter.
 * Protege chamadas à Google Gemini API contra erros transientes (HTTP 429 Rate Limit, 502/503/504,
 * oscilações de rede ou falhas eventuais de parse do contrato JSON Schema).
 */

export class NonRetryableAuditError extends Error {
  /**
   * @param {string} message
   * @param {string} code
   */
  constructor(message, code = 'NON_RETRYABLE_ERROR') {
    super(message);
    this.name = 'NonRetryableAuditError';
    this.code = code;
    this.retryable = false;
  }
}

/**
 * Determina se um erro capturado é elegível para nova tentativa (retry).
 * @param {any} error
 * @returns {boolean}
 */
export function isTransientError(error) {
  if (!error) return false;
  if (error.retryable === false || error instanceof NonRetryableAuditError) {
    return false;
  }
  const status = Number(error.status || error.statusCode || 0);
  if ([408, 429, 500, 502, 503, 504].includes(status)) {
    return true;
  }
  const msg = String(error.message || '').toLowerCase();
  return (
    msg.includes('rate limit') ||
    msg.includes('429') ||
    msg.includes('timeout') ||
    msg.includes('network') ||
    msg.includes('fetch') ||
    msg.includes('econnreset') ||
    msg.includes('schema_validation_retry') ||
    msg.includes('transient')
  );
}

/**
 * Executa uma operação assíncrona com política de Retry + Exponential Backoff e Jitter.
 *
 * @template T
 * @param {(attempt: number) => Promise<T>} operationFn Função assíncrona a ser executada
 * @param {{
 *   maxRetries?: number,
 *   baseDelayMs?: number,
 *   maxDelayMs?: number,
 *   onRetry?: (info: { attempt: number, delayMs: number, error: Error }) => void
 * }} [options]
 * @returns {Promise<{ result: T, telemetry: { attempts: number, retriesUsed: number, totalBackoffMs: number, retryHistory: Array<object> } }>}
 */
export async function executeWithRetry(operationFn, options = {}) {
  const maxRetries = options.maxRetries ?? 3;
  const baseDelayMs = options.baseDelayMs ?? 220;
  const maxDelayMs = options.maxDelayMs ?? 2500;
  const onRetry = options.onRetry;

  const retryHistory = [];
  let totalBackoffMs = 0;

  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      const result = await operationFn(attempt);
      return {
        result,
        telemetry: {
          attempts: attempt,
          retriesUsed: attempt - 1,
          totalBackoffMs,
          retryHistory,
        },
      };
    } catch (error) {
      const canRetry = attempt <= maxRetries && isTransientError(error);
      if (!canRetry) {
        error.retryTelemetry = {
          attempts: attempt,
          retriesUsed: attempt - 1,
          totalBackoffMs,
          retryHistory,
        };
        throw error;
      }

      // Exponential backoff com Jitter determinístico/aleatório controlado
      const exponential = Math.min(maxDelayMs, baseDelayMs * Math.pow(2, attempt - 1));
      const jitter = Math.floor(Math.random() * (baseDelayMs * 0.4));
      const delayMs = Math.min(maxDelayMs, exponential + jitter);
      totalBackoffMs += delayMs;

      const retryEvent = {
        attempt,
        delayMs,
        reason: error.message || 'Transient failure',
        timestamp: new Date().toISOString(),
      };
      retryHistory.push(retryEvent);

      if (typeof onRetry === 'function') {
        onRetry({ attempt, delayMs, error });
      }

      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  throw new Error('Retry loop exhausted unexpectedly.');
}
