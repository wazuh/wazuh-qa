import { Then, When } from 'cypress-cucumber-preprocessor/steps';
import WazuhMenu from '../../../pageobjects/wazuh-menu/wazuh-menu';

const wzMenu = new WazuhMenu();
const decoders = wzMenu.getDecoders();

When('The user press button custom decoders', () => {
  cy.wait(3000);
  decoders.getCustomDecodersButton()
    .click();
});

Then('The user should see the custom decoders', () => {
  cy.wait(3000);
  decoders.getTittle()
    .should('exist')
    .should('contain', 'Decoders');
  decoders.getTable()
    .should('exist')
    .should('be.visible');
  decoders.getTablePaginationDropdowns()
    .should('exist')
    .should('be.visible');
  decoders.getTablePaginationListPages()
    .should('exist')
    .should('be.visible');
});
