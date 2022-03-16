import { elementIsVisible } from '../../../utils/driver';
import { dataAddedSuccessfullyToast } from '../../../pageobjects/settings/sample-data.page';

Then('The add data success toasts are displayed', () => {
  elementIsVisible(dataAddedSuccessfullyToast);
  // getObject(dataAddedSuccessfullyToast).should('have.length', 3);

  cy.get(dataAddedSuccessfullyToast)
  .should('have.length', 3)
  .each(($li, index, $lis) => {
    return 'something else'
  })
  .then(($lis) => {
    expect($lis).to.have.length(3) // true
  })


});
