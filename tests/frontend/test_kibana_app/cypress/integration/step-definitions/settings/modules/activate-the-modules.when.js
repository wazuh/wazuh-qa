import { clickElement,elementIsVisible } from '../../../utils/driver';
import { MODULES_SETTINGS } from '../../../utils/mappers/modules-mapper';

When('The user activates/deactivates the modules with {}', (moduleName) => {
    elementIsVisible(MODULES_SETTINGS[moduleName]);
    clickElement(MODULES_SETTINGS[moduleName]);
    cy.wait(2000)
});
