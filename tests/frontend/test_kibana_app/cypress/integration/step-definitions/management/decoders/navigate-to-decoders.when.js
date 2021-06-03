import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, validateURLIncludes } from '../../../utils/driver';
import {
  decodersLink,
  wazuhMenuButton,
  managementButton,
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

When('The user navigates to decoders', () => {
  clickElement(wazuhMenuButton);
  clickElement(managementButton);
<<<<<<< HEAD
  clickElement(decodersButton);
  validateURLIncludes('/manager/?tab=decoders');
=======
  clickElement(decodersLink);
  cy.wait(5000);
>>>>>>> Update selectors
});
