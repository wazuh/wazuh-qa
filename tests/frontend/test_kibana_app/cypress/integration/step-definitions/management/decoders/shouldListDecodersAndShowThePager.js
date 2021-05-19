import { Then } from 'cypress-cucumber-preprocessor/steps';
import WazuhMenu from '../../../pageobjects/wazuh-menu/wazuh-menu';

const wzMenu = new WazuhMenu();
const decoders = wzMenu.getDecoders();

Then('The user should see the decoders', () => {
  cy.wait(3000);

  decoders.getTittle()
    .should('exist')
    .should('contain', 'Decoders');
  decoders.getTable()
    .should('exist');
  decoders.getTablePaginationDropdowns()
    .should('exist')
    .should('be.visible');
  decoders.getTablePaginationListPages()
    .should('exist')
    .should('be.visible');
});
