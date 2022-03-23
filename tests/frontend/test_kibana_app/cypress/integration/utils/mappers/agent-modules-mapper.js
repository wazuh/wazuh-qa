import {
agSecurityEventsLink,
agIntegrityMonitoringLink,
agSCALink,
agSystemAuditingLink,
agVulnerabilitiesLink,
agMitreAttackLink,
agPolicyMonitoring,
agPCIDSS,
agGDPR,
agHIPAA,
agNIST,
agTSC
  } from '../../pageobjects/agents/agents.page';
  
  export const AGENT_MODULES = {
    'Security Events': agSecurityEventsLink,
    'Integrity Monitoring': agIntegrityMonitoringLink,
    'SCA': agSCALink,
    'System Auditing': agSystemAuditingLink,
    'Vulnerabilities': agVulnerabilitiesLink,
    'Mitre & Attack': agMitreAttackLink,
    'Policy Monitoring': agPolicyMonitoring,
    'PCIDSS': agPCIDSS,
    'GDPR': agGDPR,
    'HIPAA': agHIPAA,
    'NIST': agNIST,
    'TSC': agTSC


  }