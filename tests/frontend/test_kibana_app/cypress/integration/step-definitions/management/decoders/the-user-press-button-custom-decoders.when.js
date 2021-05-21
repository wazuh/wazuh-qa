import { When } from 'cypress-cucumber-preprocessor/steps';
import { getObject } from '../../../utils/driver';
import { customDecodersButtonSelector } from '../../../pageobjects/wazuh-menu/decoders.page';

When('The user press button custom decoders', () => {
  cy.wait(3000);
  getObject(customDecodersButtonSelector)
    .click();
});
