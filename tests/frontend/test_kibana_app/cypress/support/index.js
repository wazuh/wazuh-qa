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

import { navigate, validateURLIncludes, setCookies } from '../integration/utils/driver';
import { LOGIN_TYPE, OVERVIEW_URL } from '../integration/utils/login-constants';
import { updateCookies, clearSession } from '../integration/utils/driver';
const cookieMock = require('../../cookie.json');
const loginMethod = 'xpack'
import './commands';

// Alternatively you can use CommonJS syntax:
// require('./commands')
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

    cy.wait(1000);

    validateURLIncludes(OVERVIEW_URL);

})

beforeEach(() => {
    cy.setSessionStorage('healthCheck', 'executed');
    setCookies(cookieMock);
})

afterEach(() => {
    //Code to Handle the Sesssion cookie in cypress.
    //Keep the Session alive when you jump to another test
    let str = [];
    cy.getCookies().then((cook) => {
        cy.log(cook);
        for (let l = 0; l < cook.length; l++) {
            if (cook.length > 0 && l == 0) {
                str[l] = cook[l].name;
                Cypress.Cookies.preserveOnce(str[l]);
            }
            else if (cook.length > 1 && l > 1) {
                str[l] = cook[l].name;
                Cypress.Cookies.preserveOnce(str[l]);
            }
        }
    })

})

after(() => {
    updateCookies();
})