import { elementTextIncludes } from '../../../utils/driver';
import { connectionSuccessToast } from '../../../pageobjects/settings/api-configuration.page';

Then('The connection success toast is displayed', () => {
  elementTextIncludes(connectionSuccessToast, 'Settings. Connection success');
});
