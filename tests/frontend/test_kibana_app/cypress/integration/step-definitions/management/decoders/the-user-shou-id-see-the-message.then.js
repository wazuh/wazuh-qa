import { Then } from 'cypress-cucumber-preprocessor/steps';
import { getObject } from '../../../utils/driver';
import {
  buttonRestartSelector,
  messageConfirmSaveSelector,
} from '../../../pageobjects/wazuh-menu/decoders.page';

Then('The user should see the message', () => {
  cy.wait(5000);
  getObject(messageConfirmSaveSelector)
    .should('have.text', 'Changes will not take effect until a restart is performed.');
  getObject(buttonRestartSelector)
    .should('exist')
    .should('be.visible');
});
