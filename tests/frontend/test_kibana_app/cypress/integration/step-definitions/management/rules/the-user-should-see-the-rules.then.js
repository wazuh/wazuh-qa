import { Then } from 'cypress-cucumber-preprocessor/steps';
import { getElement } from '../../../utils/driver';
import {
  dropdownPaginationSelector,
  listPagesSelector,
  tableSelector,
  titleSelector,
} from '../../../pageobjects/wazuh-menu/rules.page';

Then('The user should see the rules', () => {
  getElement(titleSelector)
    .should('exist')
    .should('contain', 'Rules');
  getElement(tableSelector)
    .should('exist')
    .should('be.visible');
  getElement(dropdownPaginationSelector)
    .should('exist')
    .should('be.visible');
  getElement(listPagesSelector)
    .should('exist')
    .should('be.visible');
});
