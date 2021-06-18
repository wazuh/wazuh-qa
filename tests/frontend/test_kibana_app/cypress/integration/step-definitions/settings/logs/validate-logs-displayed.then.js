import { elementIsVisible, elementTextIncludes } from '../../../utils/driver';
import { logsContainer, logsTitle } from '../../../pageobjects/settings/logs.page';
import { logsTitleText } from '../../../utils/logs-constants';

Then("The Logs are displayed", () => {
  elementIsVisible(logsTitle);
  elementTextIncludes(logsTitle, logsTitleText);
  elementIsVisible(logsContainer);
});
