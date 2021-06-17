import { clickElement, elementIsVisible } from '../../../utils/driver';
import { MODULES_CARDS, MODULES_SETTINGS } from '../../../utils/mappers/modules-mapper';
import {
  modulesButton,
  modulesDirectoryLink,
  wazuhMenuButton
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

Then('The activated modules with {} are displayed on home page', (moduleName) => {
  clickElement(wazuhMenuButton);
  clickElement(modulesButton);
  clickElement(modulesDirectoryLink);
  elementIsVisible(MODULES_CARDS[moduleName]);
});
