import {When} from "cypress-cucumber-preprocessor/steps";

import WzMenu from "../../../../pageobjects/wzMenu/WzMenu";

When('The user navigates to rules', () => {
    const wzMenu = new WzMenu();
    wzMenu.goToRules();
    cy.wait(3000);
});