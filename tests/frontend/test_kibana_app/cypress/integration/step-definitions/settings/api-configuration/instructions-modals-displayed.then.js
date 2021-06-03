import { elementIsVisible, elementTextIncludes } from '../../../utils/driver';
import {
  addNewConnectionModal,
  addNewConnectionModalTitle,
} from '../../../pageobjects/settings/api-configuration.page';

Then('The instructions modal is displayed', () => {
  elementIsVisible(addNewConnectionModal);
  elementTextIncludes(addNewConnectionModalTitle, 'Getting started');
});
