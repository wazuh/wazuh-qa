import {Given} from "cypress-cucumber-preprocessor/steps";
import Driver from "../utils/Driver";
import ODFELogin from "./ODEFLogin";
import XPackLogin from "./XPackLogin";
import { BASIC, ODFE, XPACK } from '../utils/constants';

Given('The kibana admin user is logged in using {word} authentication', (loginMethod) => {
    Cypress.on('uncaught:exception', (err, runnable) => {
        // returning false here prevents Cypress from
        // failing the test
        return false
    })

    const url = Cypress.env(loginMethod);
    Driver.navigate(url);
    cy.wait(5000);

    switch (loginMethod) {
        case XPACK :
            XPackLogin.login();
            break;
        case ODFE :
            ODFELogin.login();
            break;
        case BASIC :
            break;
        default :
            console.log(`Parameters loginMethod is: ${loginMethod}`)
            break;
    }
})
