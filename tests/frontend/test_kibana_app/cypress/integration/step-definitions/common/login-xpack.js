import { XPACK_PASSWORD, XPACK_USERNAME } from '../../utils/constants';
import XpackLoginPage from '../../pageobjects/login/xpack-login-page';
import Driver from '../../utils/driver';

class LoginXpack {
  static XPackLogin;

  static fillUsernameFieldXPack(userName) {
    Driver.fillField(XpackLoginPage.inputUsernameSelector, userName);
    return this;
  }

  static fillPasswordFieldXPack(password) {
    Driver.fillField(XpackLoginPage.inputPasswordSelector, password);
    return this;
  }

  static clickSubmitButtonXPack() {
    Driver.clickElement(XpackLoginPage.buttonSubmitSelector);
  }

  static login() {
    LoginXpack
      .fillUsernameFieldXPack(XPACK_USERNAME)
      .fillPasswordFieldXPack(XPACK_PASSWORD)
      .clickSubmitButtonXPack();
    cy.wait(12000);
  }
}

export default LoginXpack;
