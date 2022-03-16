import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement ,elementIsVisible } from '../../../utils/driver';
import {
  editDecoderButtonSelector,
  manageDecodersFilesButtonSelector,
  saveDecoderButtonSelector,
} from '../../../pageobjects/wazuh-menu/decoders.page';

When('The user presses the edit decoder button and edits it', () => {
  elementIsVisible(manageDecodersFilesButtonSelector);
  clickElement(manageDecodersFilesButtonSelector);
  elementIsVisible(editDecoderButtonSelector);
  clickElement(editDecoderButtonSelector);
  elementIsVisible(saveDecoderButtonSelector);
  clickElement(saveDecoderButtonSelector);
});
