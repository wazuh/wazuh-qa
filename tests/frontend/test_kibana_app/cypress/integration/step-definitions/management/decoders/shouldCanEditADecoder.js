import { Then, When } from 'cypress-cucumber-preprocessor/steps';
import WazuhMenu from '../../../pageobjects/wazuh-menu/wazuh-menu';

const wzMenu = new WazuhMenu();
const decoders = wzMenu.getDecoders();

When('The user presses the edit decoder button and edits it', () => {
  cy.wait(3000);
  decoders.getManageDecodersFilesButton()
    .click();
  decoders.getEditDecoderButton()
    .click();
  decoders.getSaveDecoderButton()
    .click();
});

Then('The user should see the message', () => {
  decoders.getMessageConfirmSave()
    .should('have.text', 'Changes will not take effect until a restart is performed.');
  decoders.getButtonRestart()
    .should('exist')
    .should('be.visible');
});
