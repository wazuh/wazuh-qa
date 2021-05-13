import {ODFE_PASSWORD, ODFE_USERNAME} from "../utils/constants";
import ODEFLoginPage from "../pageobjects/login/ODEFLoginPage";
import Driver from "../utils/Driver";

class ODFELogin {
    static ODEFLogin;

    static fillUsernameFieldODFE(userName) {
        Driver.fillField(ODEFLoginPage.inputUsernameSelector, userName);
        return this;
    }

    static fillPasswordFieldODFE(password) {
        Driver.fillField(ODEFLoginPage.inputPasswordSelector, password);
        return this;
    }

    static clickSubmitButtonODFE() {
        Driver.clickElement(ODEFLoginPage.buttonSubmitSelector);
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
