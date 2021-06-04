import { clickElement } from '../../../utils/driver';
import { newConnectionModalCheckConnectionButton } from '../../../pageobjects/settings/api-configuration.page';

When('The user tests the API connection from the instructions', () => {
  clickElement(newConnectionModalCheckConnectionButton);
});
