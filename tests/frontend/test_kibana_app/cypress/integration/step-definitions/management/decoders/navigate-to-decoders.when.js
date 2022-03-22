import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, validateURLIncludes, elementIsVisible } from '../../../utils/driver';
import {
  decodersLink,
  wazuhMenuButton,
  managementButton,
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

When('The user navigates to decoders', () => {
  elementIsVisible(wazuhMenuButton);
  clickElement(wazuhMenuButton);
  elementIsVisible(managementButton);
  clickElement(managementButton);
  elementIsVisible(decodersLink);
  clickElement(decodersLink);
  validateURLIncludes('/manager/?tab=decoders');
});
