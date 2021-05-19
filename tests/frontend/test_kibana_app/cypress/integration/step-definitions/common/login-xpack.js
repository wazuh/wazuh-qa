import { XPACK_PASSWORD, XPACK_USERNAME } from '../../utils/constants';
import { clickElement, fillField } from '../../utils/driver';
import {
  buttonSubmitSelector,
  inputPasswordSelector,
  inputUsernameSelector,
} from '../../pageobjects/login/odef-login-page';

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

const loginXpack = () => {
  fillUsernameFieldXPack(XPACK_USERNAME);
  fillPasswordFieldXPack(XPACK_PASSWORD);
  clickSubmitButtonXPack();
  cy.wait(12000);
};

export { loginXpack };
