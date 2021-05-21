import { When } from 'cypress-cucumber-preprocessor/steps';
import { getObject } from '../../../utils/driver';
import {
  editDecoderButtonSelector,
  manageDecodersFilesButtonSelector,
  saveDecoderButtonSelector,
} from '../../../pageobjects/wazuh-menu/decoders.page';

When('The user presses the edit decoder button and edits it', () => {
  cy.wait(3000);
  getObject(manageDecodersFilesButtonSelector)
    .click();
  getObject(editDecoderButtonSelector)
    .click();
  getObject(saveDecoderButtonSelector)
    .click();
});