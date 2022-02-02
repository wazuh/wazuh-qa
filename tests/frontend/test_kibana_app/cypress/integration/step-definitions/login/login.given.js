import { Given } from 'cypress-cucumber-preprocessor/steps';
import { navigate, validateURLIncludes, setCookies } from '../../utils/driver';
import { LOGIN_TYPE, OVERVIEW_URL } from '../../utils/login-constants';
const cookie = require('../../../fixtures/cookie.json')

Given('The kibana admin user is logged in using {} authentication',(loginMethod) => {
  
  cy.setSessionStorage('healthCheck', 'executed');
  
  Cypress.on('uncaught:exception', (err, runnable) => {
    // returning false here prevents Cypress from
    // failing the test
    return false;
  });

  setCookies(cookie)
  
  const url = Cypress.env(loginMethod);
  const login = LOGIN_TYPE[loginMethod];
  
  cy.log(`Parameter loginMethod is: ${loginMethod} and url from loginMethod is: ${url}`);
  
  navigate(url);
  //TODO: create a function to perform login the first login to capture a cookie
  // login ? login() : cy.log(`Error! loginMethod: "${loginMethod}" is not recognized`);
  
  validateURLIncludes(OVERVIEW_URL);
  
});
