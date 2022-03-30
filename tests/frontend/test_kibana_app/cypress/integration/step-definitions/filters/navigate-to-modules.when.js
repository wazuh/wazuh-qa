import { When } from 'cypress-cucumber-preprocessor/steps';
import { forceClickElement, elementIsVisible} from '../../utils/driver';
import { BASIC_MODULES } from '../../utils/mappers/basic-modules-mapper';
import {agentStatus} from '../../pageobjects/overview/overview.page'
When('The user goes to {}', (moduleName) => {
  elementIsVisible(agentStatus);
  elementIsVisible(BASIC_MODULES[moduleName]);
  forceClickElement(BASIC_MODULES[moduleName]);
});
