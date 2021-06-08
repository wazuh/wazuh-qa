import { elementIsVisible } from '../../../utils/driver';
import { dataAddedSuccessfullyToast } from '../../../pageobjects/settings/sample-data.page';

Then('The confirmation toast is displayed', () => {
  elementIsVisible(dataAddedSuccessfullyToast);
});
