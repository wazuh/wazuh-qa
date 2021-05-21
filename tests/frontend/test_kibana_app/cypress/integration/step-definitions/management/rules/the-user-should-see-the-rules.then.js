import { Then } from 'cypress-cucumber-preprocessor/steps';
import { getObject } from '../../../utils/driver';
import {
  dropdownPaginationSelector,
  listPagesSelector,
  tableSelector,
  titleSelector,
} from '../../../pageobjects/wazuh-menu/rules.page';

Then('The user should see the rules', () => {
  getObject(titleSelector)
    .should('exist')
    .should('contain', 'Rules');
  getObject(tableSelector)
    .should('exist')
    .should('be.visible');
  getObject(dropdownPaginationSelector)
    .should('exist')
    .should('be.visible');
  getObject(listPagesSelector)
    .should('exist')
    .should('be.visible');
});
