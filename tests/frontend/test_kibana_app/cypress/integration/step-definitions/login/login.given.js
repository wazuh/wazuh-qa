import { Given } from 'cypress-cucumber-preprocessor/steps';
import { navigate } from '../../utils/driver';
import { LOGIN_TYPE } from '../../utils/constants';

Given('The kibana admin user is logged in using {word} authentication', (loginMethod) => {
  Cypress.on('uncaught:exception', (err, runnable) => {
    // returning false here prevents Cypress from
    // failing the test
    return false;
  });

  const url = Cypress.env(loginMethod);
  navigate(url);
  cy.wait(5000);

  const login = LOGIN_TYPE[loginMethod] ? LOGIN_TYPE[loginMethod]() : LOGIN_TYPE['default'](loginMethod);
  login();
});
