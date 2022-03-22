import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible, validateURLIncludes } from '../../../utils/driver';
import {
  managementButton,
  wazuhMenuButton,
  rulesLink,
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

When('The user navigates to rules', () => {
  elementIsVisible(wazuhMenuButton);
  clickElement(wazuhMenuButton);
  elementIsVisible(managementButton);
  clickElement(managementButton);
  elementIsVisible(rulesLink);
  clickElement(rulesLink);
  validateURLIncludes('/manager/?tab=rules');
});
