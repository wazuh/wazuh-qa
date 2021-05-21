import { When } from 'cypress-cucumber-preprocessor/steps';
import WazuhMenu from '../../../pageobjects/wazuh-menu/wazuh-menu';

When('The user navigates to decoders', () => {
  const wzMenu = new WazuhMenu();
  wzMenu.goToDecoders();
  cy.wait(3000);
});
