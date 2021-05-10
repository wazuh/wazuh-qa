import {Then, When} from "cypress-cucumber-preprocessor/steps";
import WzMenu from "../../../../pageobjects/wzMenu/WzMenu";

const wzMenu = new WzMenu();
const decoders = wzMenu.getDecoders();

When('The user press button custom decoders', () => {
    cy.wait(3000);
    decoders.getCustomDecodersButton()
        .click()
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
