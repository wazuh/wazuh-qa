import { elementIsVisible } from '../../../utils/driver';
import {
  testConnectionCheckBox,
  testConnectionCheckBoxMarked,
} from '../../../pageobjects/settings/api-configuration.page';

Then('The connection success check box is filled', () => {
  elementIsVisible(testConnectionCheckBox);
  elementIsVisible(testConnectionCheckBoxMarked);
});
