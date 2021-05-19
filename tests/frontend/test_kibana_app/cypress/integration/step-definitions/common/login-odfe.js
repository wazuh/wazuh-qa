import { ODFE_PASSWORD, ODFE_USERNAME } from '../../utils/constants';
import OdefLoginPage from '../../pageobjects/login/odef-login-page';
import Driver from '../../utils/driver';

class ODFELogin {
  static ODEFLogin;

  static fillUsernameFieldODFE(userName) {
    Driver.fillField(OdefLoginPage.inputUsernameSelector, userName);
    return this;
  }

  static fillPasswordFieldODFE(password) {
    Driver.fillField(OdefLoginPage.inputPasswordSelector, password);
    return this;
  }

  static clickSubmitButtonODFE() {
    Driver.clickElement(OdefLoginPage.buttonSubmitSelector);
  }

  static login() {
    ODFELogin
      .fillUsernameFieldODFE(ODFE_USERNAME)
      .fillPasswordFieldODFE(ODFE_PASSWORD)
      .clickSubmitButtonODFE();
    cy.wait(12000);
  }
}

export default ODFELogin;
