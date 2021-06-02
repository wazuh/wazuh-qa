import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement } from '../../../utils/driver';
import {
  editDecoderButtonSelector,
  manageDecodersFilesButtonSelector,
  saveDecoderButtonSelector,
} from '../../../pageobjects/wazuh-menu/decoders.page';

When('The user presses the edit decoder button and edits it', () => {
  clickElement(manageDecodersFilesButtonSelector);
  clickElement(editDecoderButtonSelector);
  clickElement(saveDecoderButtonSelector);
});
