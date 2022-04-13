import { When } from 'cypress-cucumber-preprocessor/steps';
import { elementIsVisible, xpathElementIsVisible, clickElement, clickXpathElement} from '../../utils/driver';
import { removeFilterButton, stablishedFilter} from '../../pageobjects/filters/filters.page';
When('The user removes the applied filter', () => {
  elementIsVisible(stablishedFilter);
  clickElement(stablishedFilter);
  xpathElementIsVisible(removeFilterButton);
  clickXpathElement(removeFilterButton);
})
