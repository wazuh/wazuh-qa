import { clickElement } from '../../../utils/driver';
import { MODULES_SETTINGS } from '../../../utils/modules-constants';
import { storedModulesTable } from './store-module-names.given';

When('The user activates the modules', () => {
  storedModulesTable.rows().forEach((module) => {
    clickElement(MODULES_SETTINGS[module]);
  });
});
