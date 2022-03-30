import { 
    securityEventsLink,
    integrityMonitoringLink,
    policyMonitoringLink,
    systemAuditingLink,
    vulnerabilitiesLink,
    mitreAttackLink,
    pciDssLink,
    gdprLink,
    hipaaLink,
    nistLink,
    tscLink
 } from "../../pageobjects/wazuh-menu/wazuh-menu.page";
 export const BASIC_MODULES = {
    'Security Events': securityEventsLink,
    'Integrity Monitoring': integrityMonitoringLink,
    'System Auditing': systemAuditingLink,
    'Vulnerabilities': vulnerabilitiesLink,
    'Mitre & Attack': mitreAttackLink,
    'GDPR': gdprLink,
    'HIPAA': hipaaLink,
    'NIST': nistLink,
    'TSC': tscLink,
    'PCI DSS': pciDssLink,
    'Policiy Monitoring': policyMonitoringLink
  }