import { Then } from 'cypress-cucumber-preprocessor/steps';
import { getElement } from '../../../utils/driver';
import {
  buttonRestartSelector,
  messageConfirmSaveSelector,
} from '../../../pageobjects/wazuh-menu/decoders.page';

Then('The user should see the message', () => {
  getElement(messageConfirmSaveSelector)
    .should('have.text', 'Changes will not take effect until a restart is performed.');
  getElement(buttonRestartSelector)
    .should('exist')
    .should('be.visible');
});
