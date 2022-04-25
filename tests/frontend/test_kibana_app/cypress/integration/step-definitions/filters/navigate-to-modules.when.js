import { When } from 'cypress-cucumber-preprocessor/steps';
import { xpathElementIsVisible, forceClickElementByXpath} from '../../utils/driver';
import { BASIC_MODULES } from '../../utils/mappers/basic-modules-mapper';
When('The user goes to {}', (moduleName) => {
  xpathElementIsVisible(BASIC_MODULES[moduleName]);
  forceClickElementByXpath(BASIC_MODULES[moduleName]);
});
