import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement } from '../../../utils/driver';
import {
  decodersButton,
  wazuhButton,
  managementButton,
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

When('The user navigates to decoders', () => {
  clickElement(wazuhButton);
  clickElement(managementButton);
  clickElement(decodersButton);
  cy.wait(5000);
});
