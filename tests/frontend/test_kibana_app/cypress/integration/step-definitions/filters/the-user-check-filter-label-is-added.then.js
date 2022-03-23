import { Then } from 'cypress-cucumber-preprocessor/steps';
import { elementIsVisible, getElement} from '../../utils/driver';
import {
    stablishedFilter,
    eventsLabelSelector
  } from '../../pageobjects/filters/filters.page';

Then('The user check filter label is added', () => {
  elementIsVisible(stablishedFilter);
  });
