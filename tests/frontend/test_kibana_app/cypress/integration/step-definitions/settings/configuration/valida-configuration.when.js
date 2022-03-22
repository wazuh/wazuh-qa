import { elementTextIncludes, elementIsVisible } from '../../../utils/driver';
import {
    settingTitle,
    generalPanelTitle,
    generalPanelIndexPatternName,
    generalPanelIndexPatternDescription,
    generalPanelIndexPatternLabel,
    generalPanelIndexPatternField,
    generalPanelRequestTimeoutName,
    generalPanelRequestTimeoutDescription,
    generalPanelRequestLabel,
    generalPanelRequestField,
    generalPanelIpSelectorName,
    generalPanelIpSelectorDescription,
    generalPanelIpSelectorLabel,
    generalPanelIpSelectorField,
    generalPanelIpIgnoreName,
    generalPanelIpIgnoreDescription,
    generalPanelIpIgnoreLabel,
    generalPanelIpIgnoreField,
    generalPanelCronPrefixName,
    generalPanelCronPrefixDescription,
    generalPanelCronLabel,
    generalPanelCronField,
    generalPanelSamplePrefixName,
    generalPanelSamplePrefixDescription,
    generalPanelSampleLabel,
    generalPanelSampleField,
    generalPanelManagerAlertsPrefixName,
    generalPanelManagerAlertsPrefixDescription,
    generalPanelManagerAlertsLabel,
    generalPanelManagerAlertsField,
    generalPanelLogLevelName,
    generalPanelLogLevelDescription,
    generalPanelLogLevelLabel,
    generalPanelLogLevelField,
    generalPanelEnrollmentName,
    generalPanelEnrollmentDescription,
    generalPanelEnrollmentLabel,
    generalPanelEnrollmentField,
    healthCheckPanelTitle,
    healthCheckPanelIndexPatternPrefixName,
    healthCheckPanelIndexPatternPrefixDescription,
    healthCheckPanelIndexPatterLabel,
    healthCheckPanelIndexPatterField,
    healthCheckPanelIndexTemplatePrefixName,
    healthCheckPanelIndexTemplatePrefixDescription,
    healthCheckPanelIndexTemplateLabel,
    healthCheckPanelIndexTemplateField,
    healthCheckPanelApiConnectionPrefixName,
    healthCheckPanelApiConnectionPrefixDescription,
    healthCheckPanelApiConnectionLabel,
    healthCheckPanelApiConnectionField,
    healthCheckPanelApiVersionPrefixName,
    healthCheckPanelApiVersionPrefixDescription,
    healthCheckPanelApiVersionLabel,
    healthCheckPanelApiVersionField,
    healthCheckPanelKnowFieldsPrefixName,
    healthCheckPanelKnowFieldsPrefixDescription,
    healthCheckPanelKnowFieldsLabel,
    healthCheckPanelKnowFieldsField,
    healthCheckPanelRemoveMetaFieldsPrefixName,
    healthCheckPanelRemoveMetaFieldsPrefixDescription,
    healthCheckPanelRemoveMetaFieldsPrefixLabel,
    healthCheckPanelRemoveMetaFieldsPrefixField,
    healthCheckPanelSetBucketPrefixName,
    healthCheckPanelSetBucketPrefixDescription,
    healthCheckPanelSetBucketLabel,
    healthCheckPanelSetBucketField,
    healthCheckPanelSetTimePrefixName,
    healthCheckPanelSetTimePrefixDescription,
    healthCheckPanelSetTimeLabel,
    healthCheckPanelSetTimeField,
    monitoringPanelTitle,
    monitoringPanelStatusName,
    monitoringPanelStatusDescription,
    monitoringPanelStatusPatterLabel,
    monitoringPanelStatusPatterField,
    monitoringPanelFrequencyName,
    monitoringPanelFrequencyDescription,
    monitoringPanelFrequencyLabel,
    monitoringPanelFrequencyField,
    monitoringPanelIndexShardsName,
    monitoringPanelIndexShardsDescription,
    monitoringPanelIndexShardsLabel,
    monitoringPanelIndexShardsField,
    monitoringPanelIndexReplicasName,
    monitoringPanelIndexReplicasDescription,
    monitoringPanelPanelIndexReplicasLabel,
    monitoringPanelIndexReplicasField,
    monitoringPanelIndexCreationName,
    monitoringPanelIndexCreationDescription,
    monitoringPanelIndexCreationLabel,
    monitoringPanelIndexCreationField,
    monitoringPanelIndexPatternName,
    monitoringPanelIndexPatternDescription,
    monitoringPanelIndexPatternLabel,
    monitoringPanelIndexPatternField,
    statisticsPanelTitle,
    StatisticsPanelStatusName,
    StatisticsPanelStatusDescription,
    StatisticsPanelStatusPatterLabel,
    StatisticsPanelStatusPatterField,
    StatisticsPanelIncludesApisName,
    StatisticsPanelIncludesApisDescription,
    StatisticsPanelIncludesApisLabel,
    StatisticsPanelIncludesApisField,
    StatisticsPanelIndexIntervalName,
    StatisticsPanelIndexIntervalDescription,
    StatisticsPanelIndexIntervalLabel,
    StatisticsPanelIndexIntervalField,
    StatisticsPanelIndexNameName,
    StatisticsPanelIndexNameDescription,
    StatisticsPanelIndexNameLabel,
    StatisticsPanelIndexNameField,
    StatisticsPanelIndexCreationName,
    StatisticsPanelIndexCreationDescription,
    StatisticsPanelIndexCreationLabel,
    StatisticsPanelIndexCreationField,
    StatisticsPanelIndexShardsName,
    StatisticsPanelIndexShardsDescription,
    StatisticsPanelIndexShardsLabel,
    StatisticsPanelIndexShardsField,
    StatisticsPanelIndexReplicasName,
    StatisticsPanelIndexReplicasDescription,
    StatisticsPanelIndexReplicasLabel,
    StatisticsPanelIndexReplicasField,
    logoPanelTitle,
    LogosCustomizationPanelLogoAppName,
    LogosCustomizationPanelLogoAppDescription,
    LogosCustomizationPanelLogoAppPatterLabel,
    LogosCustomizationPanelLogoAppPatterField,
    LogosCustomizationPanelLogosSidebarName,
    LogosCustomizationPanelLogosSidebarDescription,
    LogosCustomizationPanelLogosSidebarLabel,
    LogosCustomizationPanelLogosSidebarField,
    LogosCustomizationPanelLogoHealthCheckName,
    LogosCustomizationPanelLogoHealthCheckDescription,
    LogosCustomizationPanelLogoHealthCheckLabel,
    LogosCustomizationPanelLogoHealthCheckField,
    LogosCustomizationPanelLogoReportName,
    LogosCustomizationPanelLogoReportDescription,
    LogosCustomizationPanelLogoReportLabel,
    LogosCustomizationPanelLogoReportField,
    settingSubTitle
} from '../../../pageobjects/settings/configuration.page';
const texts = require('../../../../fixtures/configuration.panel.text.json');

Then('The app current settings are displayed', () => {
    elementTextIncludes(settingTitle, texts.configurationTitle);
    elementTextIncludes(settingSubTitle, texts.configurationDescription);
    
    elementIsVisible(generalPanelTitle);
    elementIsVisible(generalPanelIndexPatternName);
    elementIsVisible(generalPanelIndexPatternDescription);
    elementIsVisible(generalPanelIndexPatternLabel);
    elementIsVisible(generalPanelIndexPatternField);
    elementIsVisible(generalPanelRequestTimeoutName);
    elementIsVisible(generalPanelRequestTimeoutDescription);
    elementIsVisible(generalPanelRequestLabel);
    elementIsVisible(generalPanelRequestField);
    elementIsVisible(generalPanelIpSelectorName);
    elementIsVisible(generalPanelIpSelectorDescription);
    elementIsVisible(generalPanelIpSelectorLabel);
    elementIsVisible(generalPanelIpSelectorField);
    elementIsVisible(generalPanelIpIgnoreName);
    elementIsVisible(generalPanelIpIgnoreDescription);
    elementIsVisible(generalPanelIpIgnoreLabel);
    elementIsVisible(generalPanelIpIgnoreField);
    elementIsVisible(generalPanelCronPrefixName);
    elementIsVisible(generalPanelCronPrefixDescription);
    elementIsVisible(generalPanelCronLabel);
    elementIsVisible(generalPanelCronField);
    elementIsVisible(generalPanelSamplePrefixName);
    elementIsVisible(generalPanelSamplePrefixDescription);
    elementIsVisible(generalPanelSampleLabel);
    elementIsVisible(generalPanelSampleField);
    elementIsVisible(generalPanelManagerAlertsPrefixName);
    elementIsVisible(generalPanelManagerAlertsPrefixDescription);
    elementIsVisible(generalPanelManagerAlertsLabel);
    elementIsVisible(generalPanelManagerAlertsField);
    elementIsVisible(generalPanelLogLevelName);
    elementIsVisible(generalPanelLogLevelDescription);
    elementIsVisible(generalPanelLogLevelLabel);
    elementIsVisible(generalPanelLogLevelField);
    elementIsVisible(generalPanelEnrollmentName);
    elementIsVisible(generalPanelEnrollmentDescription);
    elementIsVisible(generalPanelEnrollmentLabel);
    elementIsVisible(generalPanelEnrollmentField);
    elementIsVisible(healthCheckPanelTitle);
    elementIsVisible(healthCheckPanelIndexPatternPrefixName);
    elementIsVisible(healthCheckPanelIndexPatternPrefixDescription);
    elementIsVisible(healthCheckPanelIndexPatterLabel);
    elementIsVisible(healthCheckPanelIndexPatterField);
    elementIsVisible(healthCheckPanelIndexTemplatePrefixName);
    elementIsVisible(healthCheckPanelIndexTemplatePrefixDescription);
    elementIsVisible(healthCheckPanelIndexTemplateLabel);
    elementIsVisible(healthCheckPanelIndexTemplateField);
    elementIsVisible(healthCheckPanelApiConnectionPrefixName);
    elementIsVisible(healthCheckPanelApiConnectionPrefixDescription);
    elementIsVisible(healthCheckPanelApiConnectionLabel);
    elementIsVisible(healthCheckPanelApiConnectionField);
    elementIsVisible(healthCheckPanelApiVersionPrefixName);
    elementIsVisible(healthCheckPanelApiVersionPrefixDescription);
    elementIsVisible(healthCheckPanelApiVersionLabel);
    elementIsVisible(healthCheckPanelApiVersionField);
    elementIsVisible(healthCheckPanelKnowFieldsPrefixName);
    elementIsVisible(healthCheckPanelKnowFieldsPrefixDescription);
    elementIsVisible(healthCheckPanelKnowFieldsLabel);
    elementIsVisible(healthCheckPanelKnowFieldsField);
    elementIsVisible(healthCheckPanelRemoveMetaFieldsPrefixName);
    elementIsVisible(healthCheckPanelRemoveMetaFieldsPrefixDescription);
    elementIsVisible(healthCheckPanelRemoveMetaFieldsPrefixLabel);
    elementIsVisible(healthCheckPanelRemoveMetaFieldsPrefixField);
    elementIsVisible(healthCheckPanelSetBucketPrefixName);
    elementIsVisible(healthCheckPanelSetBucketPrefixDescription);
    elementIsVisible(healthCheckPanelSetBucketLabel);
    elementIsVisible(healthCheckPanelSetBucketField);
    elementIsVisible(healthCheckPanelSetTimePrefixName);
    elementIsVisible(healthCheckPanelSetTimePrefixDescription);
    elementIsVisible(healthCheckPanelSetTimeLabel);
    elementIsVisible(healthCheckPanelSetTimeField);

    elementIsVisible(monitoringPanelTitle);
    elementIsVisible(monitoringPanelStatusName);
    elementIsVisible(monitoringPanelStatusDescription);
    elementIsVisible(monitoringPanelStatusPatterLabel);
    elementIsVisible(monitoringPanelStatusPatterField);
    elementIsVisible(monitoringPanelFrequencyName);
    elementIsVisible(monitoringPanelFrequencyDescription);
    elementIsVisible(monitoringPanelFrequencyLabel);
    elementIsVisible(monitoringPanelFrequencyField);
    elementIsVisible(monitoringPanelIndexShardsName);
    elementIsVisible(monitoringPanelIndexShardsDescription);
    elementIsVisible(monitoringPanelIndexShardsLabel);
    elementIsVisible(monitoringPanelIndexShardsField);
    elementIsVisible(monitoringPanelIndexReplicasName);
    elementIsVisible(monitoringPanelIndexReplicasDescription);
    elementIsVisible(monitoringPanelPanelIndexReplicasLabel);
    elementIsVisible(monitoringPanelIndexReplicasField);
    elementIsVisible(monitoringPanelIndexCreationName);
    elementIsVisible(monitoringPanelIndexCreationDescription);
    elementIsVisible(monitoringPanelIndexCreationLabel);
    elementIsVisible(monitoringPanelIndexCreationField);
    elementIsVisible(monitoringPanelIndexPatternName);
    elementIsVisible(monitoringPanelIndexPatternDescription);
    elementIsVisible(monitoringPanelIndexPatternLabel);
    elementIsVisible(monitoringPanelIndexPatternField);

    elementIsVisible(statisticsPanelTitle);
    elementIsVisible(StatisticsPanelStatusName);
    elementIsVisible(StatisticsPanelStatusDescription);
    elementIsVisible(StatisticsPanelStatusPatterLabel);
    elementIsVisible(StatisticsPanelStatusPatterField);
    elementIsVisible(StatisticsPanelIncludesApisName);
    elementIsVisible(StatisticsPanelIncludesApisDescription);
    elementIsVisible(StatisticsPanelIncludesApisLabel);
    elementIsVisible(StatisticsPanelIncludesApisField);
    elementIsVisible(StatisticsPanelIndexIntervalName);
    elementIsVisible(StatisticsPanelIndexIntervalDescription);
    elementIsVisible(StatisticsPanelIndexIntervalLabel);
    elementIsVisible(StatisticsPanelIndexIntervalField);
    elementIsVisible(StatisticsPanelIndexNameName);
    elementIsVisible(StatisticsPanelIndexNameDescription);
    elementIsVisible(StatisticsPanelIndexNameLabel);
    elementIsVisible(StatisticsPanelIndexNameField);
    elementIsVisible(StatisticsPanelIndexCreationName);
    elementIsVisible(StatisticsPanelIndexCreationDescription);
    elementIsVisible(StatisticsPanelIndexCreationLabel);
    elementIsVisible(StatisticsPanelIndexCreationField);
    elementIsVisible(StatisticsPanelIndexShardsName);
    elementIsVisible(StatisticsPanelIndexShardsDescription);
    elementIsVisible(StatisticsPanelIndexShardsLabel);
    elementIsVisible(StatisticsPanelIndexShardsField);
    elementIsVisible(StatisticsPanelIndexReplicasName);
    elementIsVisible(StatisticsPanelIndexReplicasDescription);
    elementIsVisible(StatisticsPanelIndexReplicasLabel);
    elementIsVisible(StatisticsPanelIndexReplicasField);

    elementIsVisible(logoPanelTitle);
    elementIsVisible(LogosCustomizationPanelLogoAppName);
    elementIsVisible(LogosCustomizationPanelLogoAppDescription);
    elementIsVisible(LogosCustomizationPanelLogoAppPatterLabel);
    elementIsVisible(LogosCustomizationPanelLogoAppPatterField);
    elementIsVisible(LogosCustomizationPanelLogosSidebarName);
    elementIsVisible(LogosCustomizationPanelLogosSidebarDescription);
    elementIsVisible(LogosCustomizationPanelLogosSidebarLabel);
    elementIsVisible(LogosCustomizationPanelLogosSidebarField);
    elementIsVisible(LogosCustomizationPanelLogoHealthCheckName);
    elementIsVisible(LogosCustomizationPanelLogoHealthCheckDescription);
    elementIsVisible(LogosCustomizationPanelLogoHealthCheckLabel);
    elementIsVisible(LogosCustomizationPanelLogoHealthCheckField);
    elementIsVisible(LogosCustomizationPanelLogoReportName);
    elementIsVisible(LogosCustomizationPanelLogoReportDescription);
    elementIsVisible(LogosCustomizationPanelLogoReportLabel);
    elementIsVisible(LogosCustomizationPanelLogoReportField);


    //check the title, subtitle and label texts
    elementTextIncludes(generalPanelTitle, texts.Panel[0].name);
    elementTextIncludes(generalPanelIndexPatternName, texts.Panel[0].items[0].title );
    elementTextIncludes(generalPanelIndexPatternDescription, texts.Panel[0].items[0].subTitle );
    elementTextIncludes(generalPanelIndexPatternLabel, texts.Panel[0].items[0].label);
    elementTextIncludes(generalPanelRequestTimeoutName, texts.Panel[0].items[1].title );
    elementTextIncludes(generalPanelRequestTimeoutDescription, texts.Panel[0].items[1].subTitle );
    elementTextIncludes(generalPanelRequestLabel, texts.Panel[0].items[1].label );
    elementTextIncludes(generalPanelIpSelectorName, texts.Panel[0].items[2].title );
    elementTextIncludes(generalPanelIpSelectorDescription, texts.Panel[0].items[2].subTitle );
    elementTextIncludes(generalPanelIpSelectorLabel, texts.Panel[0].items[2].label );
    elementTextIncludes(generalPanelIpIgnoreName, texts.Panel[0].items[3].title );
    elementTextIncludes(generalPanelIpIgnoreDescription, texts.Panel[0].items[3].subTitle );
    elementTextIncludes(generalPanelIpIgnoreLabel, texts.Panel[0].items[3].label );
    elementTextIncludes(generalPanelCronPrefixName, texts.Panel[0].items[4].title );
    elementTextIncludes(generalPanelCronPrefixDescription, texts.Panel[0].items[4].subTitle );
    elementTextIncludes(generalPanelCronLabel, texts.Panel[0].items[4].label );
    elementTextIncludes(generalPanelSamplePrefixName, texts.Panel[0].items[5].title );
    elementTextIncludes(generalPanelSamplePrefixDescription, texts.Panel[0].items[5].subTitle );
    elementTextIncludes(generalPanelManagerAlertsPrefixName, texts.Panel[0].items[6].title );
    elementTextIncludes(generalPanelManagerAlertsPrefixDescription, texts.Panel[0].items[6].subTitle );
    elementTextIncludes(generalPanelManagerAlertsLabel, texts.Panel[0].items[6].label );
    elementTextIncludes(generalPanelLogLevelName, texts.Panel[0].items[7].title );
    elementTextIncludes(generalPanelLogLevelDescription, texts.Panel[0].items[7].subTitle );
    elementTextIncludes(generalPanelLogLevelLabel, texts.Panel[0].items[7].label );
    elementTextIncludes(generalPanelEnrollmentName, texts.Panel[0].items[8].title );
    elementTextIncludes(generalPanelEnrollmentDescription, texts.Panel[0].items[8].subTitle );
    elementTextIncludes(generalPanelEnrollmentLabel, texts.Panel[0].items[8].label );


    elementTextIncludes(healthCheckPanelTitle, texts.Panel[1].name );
    elementTextIncludes(healthCheckPanelIndexPatternPrefixName, texts.Panel[1].items[0].title );
    elementTextIncludes(healthCheckPanelIndexPatternPrefixDescription, texts.Panel[1].items[0].subTitle );
    elementTextIncludes(healthCheckPanelIndexPatterLabel, texts.Panel[1].items[0].label );
    elementTextIncludes(healthCheckPanelIndexTemplatePrefixName, texts.Panel[1].items[1].title );
    elementTextIncludes(healthCheckPanelIndexTemplatePrefixDescription, texts.Panel[1].items[1].subTitle );
    elementTextIncludes(healthCheckPanelIndexTemplateLabel, texts.Panel[1].items[1].label );
    elementTextIncludes(healthCheckPanelApiConnectionPrefixName, texts.Panel[1].items[2].title );
    elementTextIncludes(healthCheckPanelApiConnectionPrefixDescription, texts.Panel[1].items[2].subTitle );
    elementTextIncludes(healthCheckPanelApiConnectionLabel, texts.Panel[1].items[2].label );
    elementTextIncludes(healthCheckPanelApiVersionPrefixName, texts.Panel[1].items[3].title );
    elementTextIncludes(healthCheckPanelApiVersionPrefixDescription, texts.Panel[1].items[3].subTitle );
    elementTextIncludes(healthCheckPanelApiVersionLabel, texts.Panel[1].items[3].label );
    elementTextIncludes(healthCheckPanelKnowFieldsPrefixName, texts.Panel[1].items[4].title );
    elementTextIncludes(healthCheckPanelKnowFieldsPrefixDescription, texts.Panel[1].items[4].subTitle );
    elementTextIncludes(healthCheckPanelKnowFieldsLabel, texts.Panel[1].items[4].label );
    elementTextIncludes(healthCheckPanelRemoveMetaFieldsPrefixName, texts.Panel[1].items[5].title );
    elementTextIncludes(healthCheckPanelRemoveMetaFieldsPrefixDescription, texts.Panel[1].items[5].subTitle );
    elementTextIncludes(healthCheckPanelRemoveMetaFieldsPrefixLabel, texts.Panel[1].items[5].label );
    elementTextIncludes(healthCheckPanelSetBucketPrefixName, texts.Panel[1].items[6].title );
    elementTextIncludes(healthCheckPanelSetBucketPrefixDescription, texts.Panel[1].items[6].subTitle );
    elementTextIncludes(healthCheckPanelSetBucketLabel, texts.Panel[1].items[6].label );
    elementTextIncludes(healthCheckPanelSetTimePrefixName, texts.Panel[1].items[7].title );
    elementTextIncludes(healthCheckPanelSetTimePrefixDescription, texts.Panel[1].items[7].subTitle );
    elementTextIncludes(healthCheckPanelSetTimeLabel, texts.Panel[1].items[7].label );

    
    elementTextIncludes(monitoringPanelTitle, texts.Panel[2].name );

    elementTextIncludes(monitoringPanelStatusName, texts.Panel[2].items[0].title );
    elementTextIncludes(monitoringPanelStatusDescription, texts.Panel[2].items[0].subTitle );
    elementTextIncludes(monitoringPanelStatusPatterLabel, texts.Panel[2].items[0].label );
    elementTextIncludes(monitoringPanelFrequencyName, texts.Panel[2].items[1].title );
    elementTextIncludes(monitoringPanelFrequencyDescription, texts.Panel[2].items[1].subTitle );
    elementTextIncludes(monitoringPanelFrequencyLabel, texts.Panel[2].items[1].label );
    elementTextIncludes(monitoringPanelIndexShardsName, texts.Panel[2].items[2].title );
    elementTextIncludes(monitoringPanelIndexShardsDescription, texts.Panel[2].items[2].subTitle );
    elementTextIncludes(monitoringPanelIndexShardsLabel, texts.Panel[2].items[2].label );
    elementTextIncludes(monitoringPanelIndexReplicasName, texts.Panel[2].items[3].title );
    elementTextIncludes(monitoringPanelIndexReplicasDescription, texts.Panel[2].items[3].subTitle );
    elementTextIncludes(monitoringPanelPanelIndexReplicasLabel, texts.Panel[2].items[3].label );
    elementTextIncludes(monitoringPanelIndexCreationName, texts.Panel[2].items[4].title );
    elementTextIncludes(monitoringPanelIndexCreationDescription, texts.Panel[2].items[4].subTitle );
    elementTextIncludes(monitoringPanelIndexCreationLabel, texts.Panel[2].items[4].label );
    elementTextIncludes(monitoringPanelIndexPatternName, texts.Panel[2].items[5].title );
    elementTextIncludes(monitoringPanelIndexPatternDescription, texts.Panel[2].items[5].subTitle );
    elementTextIncludes(monitoringPanelIndexPatternLabel, texts.Panel[2].items[5].label );

    elementTextIncludes(statisticsPanelTitle,                     texts.Panel[3].name );
    elementTextIncludes(StatisticsPanelStatusName,                texts.Panel[3].items[0].title );
    elementTextIncludes(StatisticsPanelStatusDescription,         texts.Panel[3].items[0].subTitle );
    elementTextIncludes(StatisticsPanelStatusPatterLabel,         texts.Panel[3].items[0].label );
    elementTextIncludes(StatisticsPanelIncludesApisName,          texts.Panel[3].items[1].title );
    elementTextIncludes(StatisticsPanelIncludesApisDescription,   texts.Panel[3].items[1].subTitle );
    elementTextIncludes(StatisticsPanelIncludesApisLabel,         texts.Panel[3].items[1].label );
    elementTextIncludes(StatisticsPanelIndexIntervalName,         texts.Panel[3].items[2].title );
    elementTextIncludes(StatisticsPanelIndexIntervalDescription,  texts.Panel[3].items[2].subTitle );
    elementTextIncludes(StatisticsPanelIndexIntervalLabel,        texts.Panel[3].items[2].label );
    elementTextIncludes(StatisticsPanelIndexNameName,             texts.Panel[3].items[3].title );
    elementTextIncludes(StatisticsPanelIndexNameDescription,      texts.Panel[3].items[3].subTitle );
    elementTextIncludes(StatisticsPanelIndexNameLabel,            texts.Panel[3].items[3].label );
    elementTextIncludes(StatisticsPanelIndexCreationName,         texts.Panel[3].items[4].title );
    elementTextIncludes(StatisticsPanelIndexCreationDescription,  texts.Panel[3].items[4].subTitle );
    elementTextIncludes(StatisticsPanelIndexCreationLabel,        texts.Panel[3].items[4].label );
    elementTextIncludes(StatisticsPanelIndexShardsName,         texts.Panel[3].items[5].title );
    elementTextIncludes(StatisticsPanelIndexShardsDescription,  texts.Panel[3].items[5].subTitle );
    elementTextIncludes(StatisticsPanelIndexShardsLabel,        texts.Panel[3].items[5].label );
    elementTextIncludes(StatisticsPanelIndexReplicasName,           texts.Panel[3].items[6].title );
    elementTextIncludes(StatisticsPanelIndexReplicasDescription,    texts.Panel[3].items[6].subTitle );
    elementTextIncludes(StatisticsPanelIndexReplicasLabel,          texts.Panel[3].items[6].label );
    elementTextIncludes(logoPanelTitle, texts.Panel[4].name );
    elementTextIncludes(LogosCustomizationPanelLogoAppName, texts.Panel[4].items[0].title );
    elementTextIncludes(LogosCustomizationPanelLogoAppDescription, texts.Panel[4].items[0].subTitle );
    elementTextIncludes(LogosCustomizationPanelLogoAppPatterLabel, texts.Panel[4].items[0].label );
    elementTextIncludes(LogosCustomizationPanelLogosSidebarName, texts.Panel[4].items[1].title );
    elementTextIncludes(LogosCustomizationPanelLogosSidebarDescription, texts.Panel[4].items[1].subTitle );
    elementTextIncludes(LogosCustomizationPanelLogosSidebarLabel, texts.Panel[4].items[1].label );
    elementTextIncludes(LogosCustomizationPanelLogoHealthCheckName, texts.Panel[4].items[2].title );
    elementTextIncludes(LogosCustomizationPanelLogoHealthCheckDescription, texts.Panel[4].items[2].subTitle );
    elementTextIncludes(LogosCustomizationPanelLogoHealthCheckLabel, texts.Panel[4].items[2].label );
    elementTextIncludes(LogosCustomizationPanelLogoReportName, texts.Panel[4].items[3].title );
    elementTextIncludes(LogosCustomizationPanelLogoReportDescription, texts.Panel[4].items[3].subTitle );
    elementTextIncludes(LogosCustomizationPanelLogoReportLabel, texts.Panel[4].items[3].label );
})