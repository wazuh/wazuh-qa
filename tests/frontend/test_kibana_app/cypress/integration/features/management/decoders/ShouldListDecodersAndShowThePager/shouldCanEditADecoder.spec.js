import {Then, When} from "cypress-cucumber-preprocessor/steps";
import WzMenu from "../../../../pageobjects/wzMenu/WzMenu";

const wzMenu = new WzMenu();
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
        .should('have.text', 'Changes will not take effect until a restart is performed.')
    decoders.getButtonRestart()
        .should('exist')
        .should('be.visible');
});
