import { clickElement, getObject } from '../../../utils/driver';
import { checkConnectionButton } from '../../../pageobjects/settings/api-configuration.page';

When('The user checks API configuration connection', () => {
  clickElement(checkConnectionButton);
});
