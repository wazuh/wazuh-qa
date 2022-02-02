import { Then } from 'cypress-cucumber-preprocessor/steps';
import { clickElement } from '../../../utils/driver';
import { customRulesButtonSelector } from '../../../pageobjects/wazuh-menu/rules.page';

Then('The user press button custom rules', () => {
  cy.wait(2000)
  clickElement(customRulesButtonSelector);
  cy.wait(2000)
});
