import { Given } from 'cypress-cucumber-preprocessor/steps';
import { navigate, elementIsVisible } from '../../utils/driver';
import { wazuhMenuButton } from '../../pageobjects/wazuh-menu/wazuh-menu.page';


Given('The kibana admin user is logged in using {} and the wazuh logo is displayed',  (loginMethod) => {
    const url = Cypress.env(loginMethod);
    
    cy.log(`Parameter url from loginMethod is: ${url}`);
    
    navigate(Cypress.env(loginMethod));
    
    elementIsVisible(wazuhMenuButton);
    
})