import { When } from 'cypress-cucumber-preprocessor/steps';
import { xpathElementIsVisible, forceXpathClickElement} from '../../utils/driver';
import { BASIC_MODULES } from '../../utils/mappers/basic-modules-mapper';
When('The user goes to {}', (moduleName) => {
  xpathElementIsVisible(BASIC_MODULES[moduleName]);
  forceXpathClickElement(BASIC_MODULES[moduleName]);
});
