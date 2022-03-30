import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible} from '../../utils/driver';
import {
  wazuhMenuButton,
  modulesButton
} from '../../pageobjects/wazuh-menu/wazuh-menu.page';
import { BASIC_MODULES } from '../../utils/mappers/basic-modules-mapper';
When('The user goes to {}', (moduleName) => {
  elementIsVisible(wazuhMenuButton);
  clickElement(wazuhMenuButton);
  clickElement(modulesButton);
  elementIsVisible(BASIC_MODULES[moduleName]);
  clickElement(BASIC_MODULES[moduleName]);
});
