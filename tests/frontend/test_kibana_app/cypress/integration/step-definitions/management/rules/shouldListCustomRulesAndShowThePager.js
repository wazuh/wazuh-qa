import { Then } from 'cypress-cucumber-preprocessor/steps';
import WazuhMenu from '../../../pageobjects/wazuh-menu/wazuh-menu';

const wzMenu = new WazuhMenu();
const rules = wzMenu.getRules();

Then('The user press button custom rules', () => {
  cy.wait(3000);
  rules.getCustomRulesButton()
    .click();
  cy.wait(3000);
});

Then('The user should see the rules', () => {
  rules.getTitle()
    .should('exist')
    .should('contain', 'Rules');
  rules.getTable()
    .should('exist')
    .should('be.visible');
  rules.getDropdownPagination()
    .should('exist')
    .should('be.visible');
  rules.getListPages()
    .should('exist')
    .should('be.visible');
});
