import { Then } from 'cypress-cucumber-preprocessor/steps';
import {getElement} from '../../utils/driver';
import {
    pinnedFilter
  } from '../../pageobjects/filters/filters.page';
Then('The user check if the filter is displayed', () => {
     getElement(pinnedFilter)
     .should('exist')
     .should('be.visible');
  });