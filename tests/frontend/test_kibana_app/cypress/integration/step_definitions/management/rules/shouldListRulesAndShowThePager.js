import { Then } from 'cypress-cucumber-preprocessor/steps';
import WazuhMenu from '../../../pageobjects/wzMenu/wazuh-menu';

const wzMenu = new WazuhMenu();
const rules = wzMenu.getRules();

Then('The user should see the rules', () => {
  rules.getTitle()
    .should('exist')
    .should('contain', 'Rules');
  rules.getTable()
    .should('exist');
  rules.getDropdownPagination()
    .should('exist')
    .should('be.visible');
  rules.getListPages()
    .should('exist')
    .should('be.visible');
});
