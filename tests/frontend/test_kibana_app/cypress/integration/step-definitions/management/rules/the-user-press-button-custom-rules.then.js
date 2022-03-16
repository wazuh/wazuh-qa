import { Then } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible } from '../../../utils/driver';
import { customRulesButtonSelector } from '../../../pageobjects/wazuh-menu/rules.page';

Then('The user press button custom rules', () => {
  elementIsVisible(customRulesButtonSelector);
  clickElement(customRulesButtonSelector);
});
