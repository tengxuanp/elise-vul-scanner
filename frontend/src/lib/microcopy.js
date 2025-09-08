/**
 * Microcopy mapping for humanizing machine-readable codes
 */

export const microcopyMap = {
  // XSS related
  'xss_reflected': 'XSS reflection detected',
  'xss_stored': 'XSS stored vulnerability',
  'xss_dom': 'DOM-based XSS',
  'xss_context_html': 'XSS in HTML context',
  'xss_context_attr': 'XSS in attribute context',
  'xss_context_js': 'XSS in JavaScript context',
  'xss_context_url': 'XSS in URL context',
  'xss_context_css': 'XSS in CSS context',
  
  // SQLi related
  'sqli_error': 'SQL injection error-based',
  'sqli_boolean': 'SQL injection boolean-based',
  'sqli_time': 'SQL injection time-based',
  'sqli_union': 'SQL injection union-based',
  'sqli_dialect_mysql': 'MySQL database detected',
  'sqli_dialect_postgresql': 'PostgreSQL database detected',
  'sqli_dialect_mssql': 'SQL Server database detected',
  'sqli_dialect_sqlite': 'SQLite database detected',
  
  // Redirect related
  'redirect_open': 'Open redirect vulnerability',
  'redirect_location': 'Redirect location header',
  'redirect_meta': 'Meta refresh redirect',
  'redirect_js': 'JavaScript redirect',
  
  // General assessment
  'probe_proof': 'Confirmed by probe',
  'ml_prioritized': 'ML prioritized payload',
  'threshold_met': 'Above decision threshold',
  'threshold_not_met': 'Below decision threshold',
  'no_parameters_detected': 'No parameters detected',
  'not_gate_matched': 'Target didn\'t match any family gate',
  'insufficient_signals': 'Signals insufficient for decision',
  'no_candidates': 'No injection candidates found',
  'network_error': 'Network error occurred',
  'timeout_error': 'Request timeout',
  'connection_refused': 'Connection refused',
  'invalid_response': 'Invalid response received',
  'ml_attempted': 'ML ranking attempted',
  'ml_fallback': 'ML fallback to defaults',
  'ml_error': 'ML processing error',
  'gated': 'Gated by ML threshold',
  'not_gated': 'Not gated by ML',
  
  // Context and escaping
  'context_html_body': 'HTML body context',
  'context_attr': 'HTML attribute context',
  'context_js_string': 'JavaScript string context',
  'context_url': 'URL context',
  'context_css': 'CSS context',
  'escaping_raw': 'No escaping applied',
  'escaping_html': 'HTML escaping applied',
  'escaping_url': 'URL encoding applied',
  'escaping_js': 'JavaScript escaping applied',
  
  // Decision reasons
  'confirmed': 'Confirmed vulnerability',
  'suspected': 'Suspected vulnerability',
  'clean': 'No vulnerability detected',
  'abstain': 'Assessment abstained',
  'not_applicable': 'Not applicable',
  'error': 'Assessment error'
};

/**
 * Humanize a machine-readable code
 * @param {string} code - The machine code to humanize
 * @returns {string} - Human-readable text
 */
export function humanizeCode(code) {
  if (!code) return 'Unknown';
  
  // Direct mapping
  if (microcopyMap[code]) {
    return microcopyMap[code];
  }
  
  // Handle arrays of codes
  if (Array.isArray(code)) {
    return code.map(humanizeCode).join(', ');
  }
  
  // Fallback: return the original code with some formatting
  return code.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

/**
 * Humanize an array of why codes
 * @param {string[]} whyCodes - Array of machine codes
 * @returns {string[]} - Array of human-readable texts
 */
export function humanizeWhyCodes(whyCodes) {
  if (!Array.isArray(whyCodes)) return [];
  return whyCodes.map(humanizeCode);
}

/**
 * Get a short description for a code (for tooltips, etc.)
 * @param {string} code - The machine code
 * @returns {string} - Short description
 */
export function getCodeDescription(code) {
  const humanized = humanizeCode(code);
  
  // Add more context for certain codes
  const descriptions = {
    'probe_proof': 'Vulnerability confirmed by micro-probe detection',
    'ml_prioritized': 'Payload selected by machine learning ranking',
    'threshold_met': 'Confidence score exceeded decision threshold',
    'threshold_not_met': 'Confidence score below decision threshold',
    'no_parameters_detected': 'No input parameters found to test',
    'not_gate_matched': 'Target does not match any vulnerability family',
    'insufficient_signals': 'Not enough evidence to make a decision',
    'gated': 'Blocked by ML confidence threshold',
    'not_gated': 'Allowed by ML confidence threshold'
  };
  
  return descriptions[code] || humanized;
}
