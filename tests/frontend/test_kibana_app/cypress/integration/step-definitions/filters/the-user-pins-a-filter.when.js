import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, getElement} from '../../utils/driver';
import { stablishedFilter, pinFilterAction, pinnedFilter} from '../../pageobjects/filters/filters.page';
When('The user pins a filter', () => {
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
  