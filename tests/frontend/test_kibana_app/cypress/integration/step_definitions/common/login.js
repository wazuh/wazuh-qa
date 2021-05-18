import { Given } from 'cypress-cucumber-preprocessor/steps';
import Driver from '../../utils/driver';
import ODFELogin from './login-odfe';
import LoginXpack from './login-xpack';
import { BASIC, ODFE, XPACK } from '../../utils/constants';

Given('The kibana admin user is logged in using {word} authentication', (loginMethod) => {
  Cypress.on('uncaught:exception', (err, runnable) => {
    // returning false here prevents Cypress from
    // failing the test
    return false;
  });

  const url = Cypress.env(loginMethod);
  Driver.navigate(url);
  cy.wait(5000);

  switch (loginMethod) {
    case XPACK :
      LoginXpack.login();
      break;
    case ODFE :
      ODFELogin.login();
      break;
    case BASIC :
      break;
    default :
      console.log(`Parameter loginMethod is: ${loginMethod}`);
      break;
  }
});
