import Rules from './rules';
import { getObject } from '../../utils/driver';
import { decodersButtonSelector } from './decoders.page';
import { rulesButtonSelector } from './rules.page';

class WazuhMenu {

  constructor() {
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
      .click();
    const button = getObject(decodersButtonSelector).eq(1);
    button.click();
  }

  goToRules() {
    this.getListButtons()
      .click();
    this.getManagementButton()
      .click();
    const button = getObject(rulesButtonSelector).eq(0);
    button.click();
  }

}

export default WazuhMenu;
