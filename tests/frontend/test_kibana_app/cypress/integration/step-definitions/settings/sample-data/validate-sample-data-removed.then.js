import { dataAddedSuccessfullyToast } from '../../../pageobjects/settings/sample-data.page';

Then('The remove data success toasts are displayed', () => {
  cy.get(dataAddedSuccessfullyToast).should('have.length', 0);
});
