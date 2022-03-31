import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible, xpathElementIsVisible, clickXpathElement} from '../../utils/driver';
import { moreLink} from '../../pageobjects/agents/agents.page';
import { AGENT_MODULES } from '../../utils/mappers/agent-modules-mapper'; 
When('The user navigates to agentModule {}', (moduleName) => {
  xpathElementIsVisible(moreLink);
  clickXpathElement(moreLink);
  elementIsVisible(AGENT_MODULES[moduleName]);
  clickElement(AGENT_MODULES[moduleName]);
  });
  