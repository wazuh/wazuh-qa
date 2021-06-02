import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, getObject } from '../../../utils/driver';
import { customDecodersButtonSelector } from '../../../pageobjects/wazuh-menu/decoders.page';

When('The user press button custom decoders', () => {
  clickElement(customDecodersButtonSelector);
});
