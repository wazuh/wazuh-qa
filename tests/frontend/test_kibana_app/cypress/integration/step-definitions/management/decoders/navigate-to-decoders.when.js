import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement } from '../../../utils/driver';
import {
  decodersButton,
  wazuhMenuButton,
  managementButton,
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

When('The user navigates to decoders', () => {
  clickElement(wazuhMenuButton);
  clickElement(managementButton);
  clickElement(decodersButton);
  cy.wait(5000);
});
