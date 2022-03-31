import { 
    securityEvents,
    integrityMonitoring,
    policyMonitoring,
    systemAuditing,
    vulnerabilities,
    mitre,
    pciDSS,
    gdpr,
    hipaa,
    nist,
    tsc
 } from "../../pageobjects/overview/overview.page";
 export const BASIC_MODULES = {
    'Security Events': securityEvents,
    'Integrity Monitoring': integrityMonitoring,
    'System Auditing': systemAuditing,
    'Vulnerabilities': vulnerabilities,
    'Mitre & Attack': mitre,
    'GDPR': gdpr,
    'HIPAA': hipaa,
    'NIST': nist,
    'TSC': tsc,
    'PCI DSS': pciDSS,
    'Policiy Monitoring': policyMonitoring
  }
  