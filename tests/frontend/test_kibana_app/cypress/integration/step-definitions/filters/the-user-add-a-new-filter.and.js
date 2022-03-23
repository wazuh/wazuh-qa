import { And } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, fillSelectorField, elementIsVisible} from '../../utils/driver';

import {
  addFilterButton,
  filterSuggestionList,
  filterOperatorList,
  filterParams,
  saveFilterButton,
  selectedOperator
} from '../../pageobjects/filters/filters.page';
 

And('The user add a new filter', () => {
  elementIsVisible(addFilterButton);
  clickElement(addFilterButton);
  fillSelectorField(filterSuggestionList,'rule.level');
  //fillSelectorField(filterOperatorList,'is');
  elementIsVisible(filterOperatorList);
  clickElement(filterOperatorList);
  clickElement(selectedOperator);
  fillSelectorField(filterParams,'7');
  clickElement(saveFilterButton);
});