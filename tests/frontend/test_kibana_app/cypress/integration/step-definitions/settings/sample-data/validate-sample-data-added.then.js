import { getObject } from '../../../utils/driver';
import { dataAddedSuccessfullyToast } from '../../../pageobjects/settings/sample-data.page';

Then('The add data success toasts are displayed', () => {
  getObject(dataAddedSuccessfullyToast).should('have.length', 3);
});
