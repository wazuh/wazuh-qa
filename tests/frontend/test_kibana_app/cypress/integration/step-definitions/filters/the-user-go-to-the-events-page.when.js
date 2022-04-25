import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElementByXpath, xpathElementIsVisible} from '../../utils/driver';
import { eventsButton} from '../../pageobjects/filters/filters.page';
When('The user moves to events page', () => {
  xpathElementIsVisible(eventsButton);
  clickElementByXpath(eventsButton);
});

