import { clickElement, elementIsVisible } from '../../../utils/driver';
import { MODULES_CARDS } from '../../../utils/mappers/modules-mapper';
import {
  modulesButton,
  modulesDirectoryLink,
  wazuhMenuButton
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

Then('The activated modules with {} are displayed on home page', (moduleName) => {
  elementIsVisible(wazuhMenuButton);
  clickElement(wazuhMenuButton);
  elementIsVisible(modulesButton);
  clickElement(modulesButton);
  elementIsVisible(modulesDirectoryLink);
  clickElement(modulesDirectoryLink);
  elementIsVisible(MODULES_CARDS[moduleName]);
});
