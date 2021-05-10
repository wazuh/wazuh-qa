class LoginPage {

    constructor() {
        this.inputUsernameSelector = 'input[data-test-subj="user-name"]';
        this.inputPasswordSelector = 'input[data-test-subj="password"]';
        this.buttonSubmitSelector = 'button[data-test-subj="submit"]';
    }

    visit() {
        cy.visit('/app/wazuh');
    }

    fillUsername(value) {
        const field = cy.get(this.inputUsernameSelector, {timeout: 17000})
        field.clear()
            .type(value);

        return this;
    }

    fillPassword(value) {
        const field = cy.get(this.inputPasswordSelector, {timeout: 17000})
        field.clear()
            .type(value);

        return this;
    }

    submit() {
        const button = cy.get(this.buttonSubmitSelector, {timeout: 17000})
        button.click();

    }
}

export default LoginPage;
