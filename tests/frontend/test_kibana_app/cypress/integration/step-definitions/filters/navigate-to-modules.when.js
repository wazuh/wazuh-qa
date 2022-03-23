import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible} from '../../utils/driver';
import {
  wazuhMenuButton,
  modulesButton,
  securityEventsLink
} from '../../pageobjects/wazuh-menu/wazuh-menu.page';
 

When('The user goes to security-event mod', () => {
  elementIsVisible(wazuhMenuButton);
  clickElement(wazuhMenuButton);
  clickElement(modulesButton);
  clickElement(securityEventsLink);
  //validateURLIncludes('/manager/?tab=decoders');
});