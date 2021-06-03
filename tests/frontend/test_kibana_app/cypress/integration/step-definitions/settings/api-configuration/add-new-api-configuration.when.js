import { clickElement, elementIsVisible, elementTextIncludes } from '../../../utils/driver';
import {
  addNewConnectionButton,
  addNewConnectionModal, addNewConnectionModalTitle,
} from '../../../pageobjects/settings/api-configuration.page';

When('The user tries to add new API configuration', () => {
  clickElement(addNewConnectionButton);
});
