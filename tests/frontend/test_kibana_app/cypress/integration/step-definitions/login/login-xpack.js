import { XPACK_PASSWORD, XPACK_USERNAME } from '../../utils/constants';
import {
  buttonSubmitSelector,
  inputPasswordSelector,
  inputUsernameSelector,
} from '../../pageobjects/login/xpack-login.page';
import { clickElement, fillField } from '../../utils/driver';

const fillUsernameFieldXPack = (userName) => {
  fillField(inputUsernameSelector, userName);
  return this;
};

const fillPasswordFieldXPack = (password) => {
  fillField(inputPasswordSelector, password);
  return this;
};

const clickSubmitButtonXPack = () => {
  clickElement(buttonSubmitSelector);
};

const loginXpack = loginMethod => {
  cy.log(`Parameter loginMethod is: ${loginMethod}`)
  fillUsernameFieldXPack(XPACK_USERNAME);
  fillPasswordFieldXPack(XPACK_PASSWORD);
  clickSubmitButtonXPack();
  cy.wait(20000);
};

export { loginXpack };
