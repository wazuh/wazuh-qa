import { Given } from 'cypress-cucumber-preprocessor/steps';
import { navigate, validateURLIncludes } from '../../utils/driver';
import { LOGIN_TYPE, OVERVIEW_URL } from '../../utils/login-constants';

Given('The kibana admin user is logged in using {} authentication', (loginMethod) => {
  Cypress.on('uncaught:exception', (err, runnable) => {
    // returning false here prevents Cypress from
    // failing the test
    return false;
  });

  const url = Cypress.env(loginMethod);
  const login = LOGIN_TYPE[loginMethod];

  cy.log(`Parameter loginMethod is: ${loginMethod} and url from loginMethod is: ${url}`);
  navigate(url);

  login ? login() : cy.log(`Error! loginMethod: "${loginMethod}" is not recognized`);

  validateURLIncludes(OVERVIEW_URL);
});
