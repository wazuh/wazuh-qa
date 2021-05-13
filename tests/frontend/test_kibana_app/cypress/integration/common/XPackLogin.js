import {XPACK_PASSWORD, XPACK_USERNAME} from "../utils/constants";
import XPackLoginPage from "../pageobjects/login/XPackLoginPage";
import Driver from "../utils/Driver";

class XPackLogin {
    static XPackLogin;

    static fillUsernameFieldXPack(userName) {
        Driver.fillField(XPackLoginPage.inputUsernameSelector, userName);
        return this;
    }

    static fillPasswordFieldXPack(password) {
        Driver.fillField(XPackLoginPage.inputPasswordSelector, password);
        return this;
    }

    static clickSubmitButtonXPack() {
        Driver.clickElement(XPackLoginPage.buttonSubmitSelector);
    }

    static login() {
        XPackLogin
            .fillUsernameFieldXPack(XPACK_USERNAME)
            .fillPasswordFieldXPack(XPACK_PASSWORD)
            .clickSubmitButtonXPack();
        cy.wait(12000);
    }
}

export default XPackLogin;
