import { clickElement, interceptAs } from '../../../utils/driver';
import { reloadLogsLink } from '../../../pageobjects/settings/logs.page';

When('The user reloads the logs', () => {
  interceptAs('GET', '/utils/logs', 'apiCheck');
  clickElement(reloadLogsLink);
});
