import { Given } from 'cypress-cucumber-preprocessor/steps';
import { navigate } from '../../utils/driver';
import { loginXpack } from './login-xpack';
import { BASIC, ODFE, XPACK } from '../../utils/constants';
import { loginOdfe } from './login-odfe';

Given('The kibana admin user is logged in using {word} authentication', (loginMethod) => {
  Cypress.on('uncaught:exception', (err, runnable) => {
    // returning false here prevents Cypress from
    // failing the test
    return false;
  });

  const url = Cypress.env(loginMethod);
  navigate(url);
  cy.wait(5000);

  switch (loginMethod) {
    case XPACK:
      loginXpack();
      break;
    case ODFE:
      loginOdfe();
      break;
    case BASIC:
      break;
    default:
      console.log(`Parameter loginMethod is: ${loginMethod}`);
      break;
  }
});
