import { When } from 'cypress-cucumber-preprocessor/steps';
<<<<<<< HEAD
import { clickElement, getElement, validateURLIncludes } from '../../../utils/driver';
=======
import { clickElement, elementIsVisible, validateURLIncludes } from '../../../utils/driver';
>>>>>>> 8b6b4b0d0 (fix the test suite)
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
