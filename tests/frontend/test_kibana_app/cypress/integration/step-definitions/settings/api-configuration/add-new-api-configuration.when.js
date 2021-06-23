import { clickElement } from '../../../utils/driver';
import { addNewConnectionButton } from '../../../pageobjects/settings/api-configuration.page';

When('The user tries to add new API configuration', () => {
  clickElement(addNewConnectionButton);
});
