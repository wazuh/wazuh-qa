import {When} from "cypress-cucumber-preprocessor/steps";
import WzMenu from "../../../../pageobjects/wzMenu/WzMenu";

When('The user navigates to decoders', () => {
    const wzMenu = new WzMenu();
    wzMenu.goToDecoders();
    cy.wait(3000);
});
