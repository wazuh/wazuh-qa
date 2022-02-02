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
import './commands';

// Alternatively you can use CommonJS syntax:
// require('./commands')

  afterEach(() => {
    //Code to Handle the Sesssion cookie in cypress.
    //Keep the Session alive when you jump to another test
    let str= [];
    debugger
    cy.getCookies().then((cook) => {
        cy.log(cook);
        for (let l = 0; l < cook.length; l++)
        {
            if(cook.length>0&&l==0){
                str[l] = cook[l].name;
                Cypress.Cookies.preserveOnce(str[l]);
            }
            else if(cook.length>1&&l>1){
                str[l] = cook[l].name;
                Cypress.Cookies.preserveOnce(str[l]);
            }
        }
    })
})