Then('The backend response indicates that the logs are reloaded', () => {
  cy.get('@apiCheck').should('not.be.null');
  //TODO validate response from the backend
});
