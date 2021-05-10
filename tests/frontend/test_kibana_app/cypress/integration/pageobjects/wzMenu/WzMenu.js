import Decoders from "./Decoders";
import Rules from "./Rules";

class WzMenu {

    constructor() {
        this.decoders = new Decoders();
        this.rules = new Rules();
    }

    getListButtons() {
        return cy.get('.eui > .euiFlexGroup');
    }

    getManagementButton() {
        return cy.get('[class="euiButtonEmpty euiButtonEmpty--text wz-menu-button "]').first();
    }

    goToDecoders() {
        this.getListButtons()
            .click();
        this.getManagementButton()
            .click()
        const button = this.decoders.getDecodersButton();
        button.click();
    }

    goToRules() {
        this.getListButtons()
            .click();
        this.getManagementButton()
            .click();
        const button = this.rules.getRulesButton();
        button.click();
    }

    getDecoders() {
        return this.decoders;
    }

    getRules() {
        return this.rules;
    }

}

export default WzMenu;
