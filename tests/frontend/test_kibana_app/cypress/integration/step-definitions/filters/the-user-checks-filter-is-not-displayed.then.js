import { Then } from 'cypress-cucumber-preprocessor/steps';
import { elementIsNotVisible} from '../../utils/driver';
import { stablishedFilter} from '../../pageobjects/filters/filters.page';
Then('The user checks filter label is not added', () => {
  elementIsNotVisible(stablishedFilter);
  });