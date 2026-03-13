const MITRE_MAP = {
  // Initial Access
  SQL_INJECTION: {
    tactic: 'Initial Access',
    technique: 'Exploit Public-Facing Application',
    id: 'T1190',
    severity: 'CRITICAL',
    description: 'Attempt to manipulate database queries via SQL injection'
  },
  
  XSS: {
    tactic: 'Execution',
    technique: 'Cross-Site Scripting',
    id: 'T1059.007',
    severity: 'HIGH',
    description: 'Script injection attempt in user-controllable input fields'
  },
  
  XSS_STORED: {
    tactic: 'Persistence',
    technique: 'Stored Cross-Site Scripting',
    id: 'T1059.007',
    severity: 'CRITICAL',
    description: 'Persistent script injection attempt'
  },
  
  BRUTE_FORCE: {
    tactic: 'Credential Access',
    technique: 'Brute Force',
    id: 'T1110',
    severity: 'HIGH',
    description: 'Repeated authentication attempts indicating brute force attack'
  },
  
  CREDENTIAL_STUFFING: {
    tactic: 'Credential Access',
    technique: 'Credential Stuffing',
    id: 'T1110.004',
    severity: 'HIGH',
    description: 'Use of previously compromised credentials'
  },
  
  PATH_TRAVERSAL: {
    tactic: 'Discovery',
    technique: 'File and Directory Discovery',
    id: 'T1083',
    severity: 'HIGH',
    description: 'Path traversal attempt to access files outside web root'
  },
  
  COMMAND_INJECTION: {
    tactic: 'Execution',
    technique: 'Command and Scripting Interpreter',
    id: 'T1059',
    severity: 'CRITICAL',
    description: 'OS command injection attempt in application parameters'
  },
  
  DIRECTORY_SCAN: {
    tactic: 'Discovery',
    technique: 'Network Service Discovery',
    id: 'T1046',
    severity: 'MEDIUM',
    description: 'Systematic scanning of web directories and endpoints'
  },
  
  FILE_UPLOAD_MALICIOUS: {
    tactic: 'Persistence',
    technique: 'Server Software Component: Web Shell',
    id: 'T1505.003',
    severity: 'CRITICAL',
    description: 'Upload of potentially malicious file (web shell attempt)'
  },
  
  XXEI: {
    tactic: 'Initial Access',
    technique: 'Exploit Public-Facing Application',
    id: 'T1190',
    severity: 'CRITICAL',
    description: 'XML External Entity injection attempt'
  },
  
  SSRF: {
    tactic: 'Discovery',
    technique: 'Internal Spearphishing',
    id: 'T1534',
    severity: 'HIGH',
    description: 'Server-Side Request Forgery attempt'
  },
  
  BOT_SCAN: {
    tactic: 'Reconnaissance',
    technique: 'Active Scanning',
    id: 'T1595',
    severity: 'MEDIUM',
    description: 'Automated scanning behavior detected'
  },
  
  HEADER_INJECTION: {
    tactic: 'Initial Access',
    technique: 'Exploit Public-Facing Application',
    id: 'T1190',
    severity: 'HIGH',
    description: 'HTTP header injection attempt'
  },
  
  CSRF: {
    tactic: 'Execution',
    technique: 'Exploitation for Client Execution',
    id: 'T1203',
    severity: 'MEDIUM',
    description: 'Cross-Site Request Forgery attempt detected'
  },
  
  RECONNAISSANCE: {
    tactic: 'Reconnaissance',
    technique: 'Gather Victim Web Info',
    id: 'T1592',
    severity: 'LOW',
    description: 'General information gathering and reconnaissance activity'
  },
};

/**
 * Map attack type string to MITRE entry
 */
function getMitreEntry(attackType) {
  return MITRE_MAP[attackType] || {
    tactic: 'Unknown',
    technique: 'Unknown Technique',
    id: 'T0000',
    severity: 'LOW',
    description: 'Unclassified suspicious activity'
  };
}

/**
 * Get all MITRE entries for reporting
 */
function getAllMitreEntries() {
  return MITRE_MAP;
}

module.exports = { getMitreEntry, getAllMitreEntries, MITRE_MAP };