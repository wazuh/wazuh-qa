export const clickElement = (selector) => {
  getElement(selector).click();
  return this;
};

export const elementIsVisible = (element) => {
  return getElement(element).should('exist').should('be.visible');
};

export const elementTextIncludes = (selector, text) => {
  getElement(selector).should('contain', text);
}

export const fillField = (selector, text) => {
  getElement(selector).clear().type(text);
  return this;
};

export const getElement = (selector) => {
  return cy.get(selector);
};

export const navigate = (url) => {
  cy.visit(url);
};

export const validateURLIncludes = (include) => {
  cy.url().should('include', include);
}
