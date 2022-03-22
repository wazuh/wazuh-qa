import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible, getAttributeElement } from '../../../utils/driver';
import { MODULES_SETTINGS } from '../../../utils/mappers/modules-mapper';

When('The user {} the modules with {}', (status, moduleName) => {
    elementIsVisible(MODULES_SETTINGS[moduleName]);
    clickElement(MODULES_SETTINGS[moduleName]);
    cy.wait(1000)
});
