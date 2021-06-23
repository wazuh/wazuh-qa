import { clickElement } from '../../../utils/driver';
import { runHealthChecksButton } from '../../../pageobjects/settings/miscellaneous.page';

When('The user runs the health checks', () => {
  clickElement(runHealthChecksButton);
});
