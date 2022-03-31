import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible} from '../../utils/driver';
import { wazuhMenuButton, modulesDirectoryLink, modulesButton} from '../../pageobjects/wazuh-menu/wazuh-menu.page';
When('The user navigates overview page', () => {
  elementIsVisible(wazuhMenuButton);
  clickElement(wazuhMenuButton);
  elementIsVisible(modulesButton);
  clickElement(modulesButton);
  elementIsVisible(modulesDirectoryLink);
  clickElement(modulesDirectoryLink);
});
