import { Then } from 'cypress-cucumber-preprocessor/steps';
import { getElement } from '../../../utils/driver';
import {
  titleSelector,
  tableSelector,
  dropdownPaginationSelector,
  listPages
} from '../../../pageobjects/wazuh-menu/decoders.page';

Then('The user should see the decoders', () => {
  getElement(titleSelector)
    .should('exist')
    .should('contain', 'Decoders');
  getElement(tableSelector)
    .should('exist');
  getElement(dropdownPaginationSelector)
    .should('exist')
    .should('be.visible');
  getElement(listPages)
    .should('exist')
    .should('be.visible');
});
