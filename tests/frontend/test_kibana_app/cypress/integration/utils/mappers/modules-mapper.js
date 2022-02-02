import {
  amazonAWSToggleButton,
  cisCatToggleButton,
  dockerListenerToggleButton,
  gCPToggleButton,
  gDPRToggleButton,
  hIPAAToggleButton,
  openSCAPToggleButton,
  osqueryToggleButton,
  tSCToggleButton,
  gitHubCardToggleButton,
  virusTotalToggleButton
} from '../../pageobjects/settings/modules.page';
import {
  amazonAWSCard,
  cisCatCard,
  dockerListenerCard,
  gCPCard,
  gDPRCard,
  hIPAACard,
  openSCAPCard,
  osqueryCard,
  tSCCard,
  gitHubCard,
  virusTotalCard
} from '../../pageobjects/modules-directory.page';

export const MODULES_CARDS = {
  'Amazon AWS': amazonAWSCard,
  'Google Cloud Platform': gCPCard,
  GitHub: gitHubCard,
  OpenSCAP: openSCAPCard,
  'CIS-CAT': cisCatCard,
  VirusTotal: virusTotalCard,
  Osquery: osqueryCard,
  'Docker listener': dockerListenerCard,
  GDPR: gDPRCard,
  HIPAA: hIPAACard,
  TSC: tSCCard
};

export const MODULES_SETTINGS = {
  'Amazon AWS': amazonAWSToggleButton,
  'Google Cloud Platform': gCPToggleButton,
  GitHub: gitHubCardToggleButton,
  OpenSCAP: openSCAPToggleButton,
  'CIS-CAT': cisCatToggleButton,
  VirusTotal: virusTotalToggleButton,
  Osquery: osqueryToggleButton,
  'Docker listener': dockerListenerToggleButton,
  GDPR: gDPRToggleButton,
  HIPAA: hIPAAToggleButton,
  TSC: tSCToggleButton
};
