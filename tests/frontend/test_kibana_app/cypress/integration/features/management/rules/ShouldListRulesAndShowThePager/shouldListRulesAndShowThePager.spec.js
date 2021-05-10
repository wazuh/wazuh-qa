import {Then} from "cypress-cucumber-preprocessor/steps";
import WzMenu from "../../../../pageobjects/wzMenu/WzMenu";

const wzMenu = new WzMenu();
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