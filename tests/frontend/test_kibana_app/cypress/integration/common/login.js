import {Given} from "cypress-cucumber-preprocessor/steps";
import {WAZUH_URL} from "../utils/constants";
import Driver from "../utils/Driver";
import ODFELogin from "./ODEFLogin";
import XPackLogin from "./XPackLogin";

Given('The kibana admin user is logged in using {word} authentication', (loginMethod) => {
    Cypress.on('uncaught:exception', (err, runnable) => {
        // returning false here prevents Cypress from
        // failing the test
        return false
    })

    Driver.navigate(WAZUH_URL)
    cy.wait(5000);

    switch (loginMethod) {
        case 'xpack' :
            XPackLogin.login();
            break;
        case 'odfe' :
            ODFELogin.login();
            break;
        default :
            break;
    }
})
