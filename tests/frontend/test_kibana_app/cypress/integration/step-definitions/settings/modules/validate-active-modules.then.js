import { storedModulesTable } from './store-module-names.given';
import { clickElement, elementIsVisible } from '../../../utils/driver';
import { MODULES_CARDS, MODULES_SETTINGS } from '../../../utils/modules-constants';
import {
  modulesButton,
  modulesDirectory, settingsButton, settingsModulesButton,
  wazuhMenuButton,
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

Then('The activated modules are displayed on home page', () => {
  clickElement(wazuhMenuButton);
  clickElement(modulesButton);
  clickElement(modulesDirectory)

  storedModulesTable.rows().forEach((module) => {
    elementIsVisible(MODULES_CARDS[module]);
  });

  //deactivate the modules after executing
  clickElement(wazuhMenuButton);
  clickElement(settingsButton);
  clickElement(settingsModulesButton)
  storedModulesTable.rows().forEach((module) => {
    clickElement(MODULES_SETTINGS[module]);
  });
});
