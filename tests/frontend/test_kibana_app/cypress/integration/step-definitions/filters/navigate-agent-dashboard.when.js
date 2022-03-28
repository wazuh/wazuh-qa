import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible} from '../../utils/driver';
import { firstAgentList, statusChart} from '../../pageobjects/agents/agents.page'; 
When('The user navigates to the agent dashboard', () => {
  elementIsVisible(statusChart);
  elementIsVisible(firstAgentList);
  clickElement(firstAgentList);
});
