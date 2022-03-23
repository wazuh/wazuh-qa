import { And } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, getElement} from '../../utils/driver';
import {
    stablishedFilter,
    pinFilterAction,
    pinnedFilter
  } from '../../pageobjects/filters/filters.page';

And('The user pin a filter', () => {
    getElement(stablishedFilter)
     .should('exist')
     .should('be.visible');
    clickElement(stablishedFilter);
    getElement(pinFilterAction)
     .should('exist')
     .should('be.visible');
    clickElement(pinFilterAction)
    getElement(pinnedFilter)
     .should('exist')
     .should('be.visible');
  });