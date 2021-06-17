import {
  addAuditingAndPolicyMonitoringDataButton,
  addSecurityInformationDataButton,
  addThreatDetectionAndResponseDataButton
} from '../../pageobjects/settings/sample-data.page';

export const SAMPLE_DATA = {
  'security information': addSecurityInformationDataButton,
  'auditing and policy monitoring': addAuditingAndPolicyMonitoringDataButton,
  'threat detection and response': addThreatDetectionAndResponseDataButton
};
