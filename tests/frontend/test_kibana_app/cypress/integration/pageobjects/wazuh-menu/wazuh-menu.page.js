export const wazuhMenuButton = '[data-test-subj=menuWazuhButton]';
//region Menu
export const modulesButton = '[data-test-subj=menuModulesButton]';
export const managementButton = '[data-test-subj=menuManagementButton]';
export const agentsButton = '[data-test-subj=menuAgentsButton]';
export const toolsButton = '[data-test-subj=menuToolsButton]';
export const securityButton = '[data-test-subj=menuSecurityButton]';
export const settingsButton = '[data-test-subj=menuSettingsButton]';
//endregion Menu
//region SubMenu
//region Modules
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
export const modulesDirectory = 'div.wz-menu-right-side > div > div > div.euiFlexGroup.euiFlexGroup--gutterLarge.euiFlexGroup--directionRow.euiFlexGroup--responsive > div > button > span > span';
export const securityEventsButton = ':nth-child(1) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(1) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const integrityMonitoringButton = ':nth-child(1) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(2) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const amazonAwsButton = ':nth-child(1) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(3) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const googleCloudPlatformButton = ':nth-child(1) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(4) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const policyMonitoringButton = ':nth-child(2) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(1) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const systemAuditingButton = ':nth-child(2) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(2) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const openScapButton = ':nth-child(2) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(3) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const cisCatButton = ':nth-child(2) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(4) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const securityConfigurationAssessmentButton = ':nth-child(2) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(5) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const vulnerabilitiesButton = ':nth-child(3) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(1) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const virusTotalButton = ':nth-child(3) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(2) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const osqueryButton = ':nth-child(3) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(3) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const dockerListenerButton = ':nth-child(3) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(4) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const mitreAttackButton = ':nth-child(3) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(5) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const pciDssButton = ':nth-child(4) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(1) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const gdprButton = ':nth-child(4) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(2) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const hipaaButton = ':nth-child(4) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(3) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const nistButton = ':nth-child(4) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(4) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
export const tscButton = ':nth-child(4) > .euiSideNav > .euiSideNav__content > .euiSideNavItem--root > .euiSideNavItem__items > :nth-child(5) > .euiSideNavItemButton > .euiSideNavItemButton__content > .euiSideNavItemButton__label';
=======
export const securityEventsLink = '[data-cy=menu-modules-general-link]';
export const integrityMonitoringLink = '[data-cy=menu-modules-fim-link]';
export const amazonAwsLink = '[data-cy=menu-modules-aws-link]';
export const googleCloudPlatformLink = '[data-cy=menu-modules-gcp-link]';
export const policyMonitoringLink = '[data-cy=menu-modules-pm-link]';
export const systemAuditingLink = '[data-cy=menu-modules-audit-link]';
export const openScapLink = '[data-cy=menu-modules-oscap-link]';
export const cisCatLink = '[data-cy=menu-modules-ciscat-link]';
export const securityConfigurationAssessmentLink = '[data-cy=menu-modules-sca-link]';
export const vulnerabilitiesLink = '[data-cy=menu-modules-vuls-link]';
export const virusTotalLink = '[data-cy=menu-modules-virustotal-link]';
export const osqueryLink ='[data-cy=menu-modules-osquery-link]';
export const dockerListenerLink = '[data-cy=menu-modules-docker-link]';
export const mitreAttackLink = '[data-cy=menu-modules-mitre-link]';
export const pciDssLink = '[data-cy=menu-modules-pci-link]';
export const gdprLink = '[data-cy=menu-modules-gdpr-link]';
export const hipaaLink = '[data-cy=menu-modules-hipaa-link]';
export const nistLink = '[data-cy=menu-modules-nist-link]';
export const tscLink = '[data-cy=menu-modules-tsc-link]';
>>>>>>> Update selectors
=======
=======
export const modulesDirectoryLink = '.wz-menu-right-side  div.euiFlexGroup > div > button > span > span';
>>>>>>> added example table, and modified scripts to run tests from CLI
export const securityEventsLink = '[data-test-subj=menuModulesSecurityEventsLink]';
export const integrityMonitoringLink = '[data-test-subj=menuModulesFimLink]';
export const amazonAwsLink = '[data-test-subj=menuModulesAwsLink]';
export const googleCloudPlatformLink = '[data-test-subj=menuModulesGcpLink]';
export const policyMonitoringLink = '[data-test-subj=menuModulesPolicyMonitoringLink]';
export const systemAuditingLink = '[data-test-subj=menuModulesAuditLink]';
export const openScapLink = '[data-test-subj=menuModulesOpenScapLink]';
export const cisCatLink = '[data-test-subj=menuModulesCiscatLink]';
export const securityConfigurationAssessmentLink = '[data-test-subj=menuModulesScaLink]';
export const vulnerabilitiesLink = '[data-test-subj=menuModulesVulsLink]';
export const virusTotalLink = '[data-test-subj=menuModulesVirustotalLink]';
export const osqueryLink ='[data-test-subj=menuModulesOsqueryLink]';
export const dockerListenerLink = '[data-test-subj=menuModulesDockerLink]';
export const mitreAttackLink = '[data-test-subj=menuModulesMitreLink]';
export const pciDssLink = '[data-test-subj=menuModulesPciLink]';
export const gdprLink = '[data-test-subj=menuModulesGdprLink]';
export const hipaaLink = '[data-test-subj=menuModulesHipaaLink]';
export const nistLink = '[data-test-subj=menuModulesNistLink]';
export const tscLink = '[data-test-subj=menuModulesTscLink]';
>>>>>>> Update selectors
//endregion
//region Management
export const rulesLink ='[data-test-subj=menuManagementRulesLink]';
export const decodersLink = '[data-test-subj=menuManagementDecodersLink]';
export const cdbListLink = '[data-test-subj=menuManagementCdbListsLink]';
export const groupsLink = '[data-test-subj=menuManagementGroupsLink]';
export const configurationLink = '[data-test-subj=menuManagementConfigurationLink]';
export const statusLink = '[data-test-subj=menuManagementStatusLink]';
export const clusterLink = '[data-test-subj=menuManagementMonitoringLink]';
export const statisticsLink = '[data-test-subj=menuManagementStatisticsLink]';
export const logsLink = '[data-test-subj=menuManagementLogsLink]';
export const reportingLink = '[data-test-subj=menuManagementReportingLink]';
//endregion
//region Tools
export const apiConsoleLink = '[data-test-subj=menuToolsDevToolsLink]';
export const rulesetTestLink = '[data-test-subj=menuToolsLogtestLink]';
//endregion
//region Security
export const usersLink = '[data-test-subj=menuSecurityUsersLink]';
export const rolesLink = '[data-test-subj=menuSecurityRolesLink]';
export const policiesLink = '[data-test-subj=menuSecurityPoliciesLink]';
export const rolesMappingLink = '[data-test-subj=menuSecurityRoleMappingLink]';
//endregion
//region Settings
export const settingsApiConfigurationLink = '[data-test-subj=menuSettingsApiLink]';
export const settingsModulesLink = '[data-test-subj=menuSettingsModulesLink]';
export const settingsSampleDataLink = '[data-test-subj=menuSettingsSampleDataLink]';
export const settingsConfigurationLink = '[data-test-subj=menuSettingsConfigurationLink]';
export const settingsLogsLink = '[data-test-subj=menuSettingsLogsLink]';
export const settingsMiscellaneousLink = '[data-test-subj=menuSettingsMiscellaneousLink]';
export const settingsAboutLink = '[data-test-subj=menuSettingsAboutLink]';
//endregion
//endregion
