import { When } from 'cypress-cucumber-preprocessor/steps';
import { getObject } from '../../../utils/driver';
import {
  menuListButtonsSelector,
  subMenuListButtonsSelector,
  wazuhButtonSelector,
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

When('The user navigates to decoders', () => {
  getObject(wazuhButtonSelector)
    .click();
  getObject(menuListButtonsSelector)
    .eq(0)
    .click();
  getObject(subMenuListButtonsSelector)
    .eq(1)
    .click();
  cy.wait(3000);
});
