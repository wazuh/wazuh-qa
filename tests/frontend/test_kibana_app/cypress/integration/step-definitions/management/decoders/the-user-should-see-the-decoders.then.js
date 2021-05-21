import { Then } from 'cypress-cucumber-preprocessor/steps';
import { getObject } from '../../../utils/driver';
import {
  titleSelector,
  tableSelector,
  dropdownPaginationSelector,
  listPages
} from '../../../pageobjects/wazuh-menu/decoders.page';

Then('The user should see the decoders', () => {
  cy.wait(3000);
  getObject(titleSelector)
    .should('exist')
    .should('contain', 'Decoders');
  getObject(tableSelector)
    .should('exist');
  getObject(dropdownPaginationSelector)
    .should('exist')
    .should('be.visible');
  getObject(listPages)
    .should('exist')
    .should('be.visible');
});
