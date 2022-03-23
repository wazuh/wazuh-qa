import { And } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible} from '../../utils/driver';
import {
    firstAgentList
  } from '../../pageobjects/agents/agents.page';
   
And('The user navigates to the agent dashboard', () => {
  cy.wait(2000);
  elementIsVisible(firstAgentList);
  clickElement(firstAgentList);
});