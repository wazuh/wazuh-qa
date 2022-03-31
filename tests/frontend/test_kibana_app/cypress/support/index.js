// ***********************************************************
// This example support/index.js is processed and
// loaded automatically before your test files.
//
// This is a great place to put global configuration and
// behavior that modifies Cypress.
//
// You can change the location of this file or turn off
// automatically serving support files with the
// 'supportFile' configuration option.
//
// You can read more here:
// https://on.cypress.io/configuration
// ***********************************************************

// Import commands.js using ES2015 syntax:

import { LOGIN_TYPE, OVERVIEW_URL } from '../integration/utils/login-constants';
import { 
    updateCookies, 
    clearSession, 
    updateExpiryValueCookies, 
    navigate, 
    validateURLIncludes, 
    setCookies, 
    preserveCookie  
} from '../integration/utils/driver';
const cookieMock = require('../../cookie.json');
const loginMethod = 'xpack'
import './commands';
require("cypress-xpath");

before(() => {
    clearSession();

    cy.setSessionStorage('healthCheck', 'executed');

    Cypress.on('uncaught:exception', (err, runnable) => {
        return false;
    });

    const url = Cypress.env(loginMethod);

    const login = LOGIN_TYPE[loginMethod];

    cy.log(`Parameter loginMethod is: ${loginMethod} and url from loginMethod is: ${url}`);

    navigate(url);

    login ? login() : cy.log(`Error! loginMethod: "${loginMethod}" is not recognized`);

    cy.wait(15000);

    validateURLIncludes(OVERVIEW_URL);

    // cy.getCookies().then((cook) => {
    //     cy.log('---> ',cook);
    // })

})

beforeEach(() => {
    // cy.getCookies().then((cook) => {
    //     cy.log('---> ',cook);
        setCookies(cook);
    // })
    cy.setSessionStorage('healthCheck', 'executed');
    updateExpiryValueCookies();
    preserveCookie()
    updateCookies();
})

afterEach(() => {
    //Code to Handle the Sesssion cookie in cypress.
    //Keep the Session alive when you jump to another test
    // let str = [];
    // cy.getCookies().then((cook) => {
    //     cy.log('after - get cookie',cook);
    //     for (let l = 0; l < cook.length; l++) {
    //         debugger
    //         if (cook.length > 0 && l == 0) {
    //             str[l] = cook[l].name;
    //             Cypress.Cookies.preserveOnce(str[l]);
    //         }
    //         else if (cook.length > 1 && l > 1) {
    //             str[l] = cook[l].name;
    //             Cypress.Cookies.preserveOnce(str[l]);
    //         }
    //     }
    // })
    // setCookies(cookieMock);
      updateCookies();

})

// after(() => {
//     cy.getCookies().then((cook) => {
//         cy.log('---> ',cook);
//     })
//     updateCookies();
// })