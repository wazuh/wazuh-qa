import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, validateURLIncludes } from '../../../utils/driver';
import {
  managementButton,
  wazuhMenuButton,
  rulesLink,
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

When('The user navigates to rules', () => {
  clickElement(wazuhMenuButton);
  clickElement(managementButton);
  clickElement(rulesLink);
  validateURLIncludes('/manager/?tab=rules');
});
