import { clickElement } from '../../../utils/driver';
import { MODULES_SETTINGS } from '../../../utils/mappers/modules-mapper';

When('The user activates/deactivates the modules with {}', (moduleName) => {
    clickElement(MODULES_SETTINGS[moduleName]);
});
