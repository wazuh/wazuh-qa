import { elementIsVisible, getElement } from '../../../utils/driver';
import {
  healthCheckContainer,
  successCheckIconList,
} from '../../../pageobjects/settings/miscellaneous.page';

Then('The health checks are displayed without errors', () => {
  elementIsVisible(healthCheckContainer);
  getElement(successCheckIconList).should('have.length', 8);
});
