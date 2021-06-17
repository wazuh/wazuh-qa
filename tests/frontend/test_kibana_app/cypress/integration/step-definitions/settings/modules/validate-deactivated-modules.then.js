import { clickElement, elementIsNotVisible, elementIsVisible } from '../../../utils/driver';
import {
  modulesButton,
  modulesDirectoryLink,
  wazuhMenuButton,
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';
import { MODULES_CARDS } from '../../../utils/mappers/modules-mapper';

Then('The deactivated modules with {} are not displayed on home page', (moduleName) => {
  clickElement(wazuhMenuButton);
  clickElement(modulesButton);
  clickElement(modulesDirectoryLink);
  elementIsNotVisible(MODULES_CARDS[moduleName]);
});