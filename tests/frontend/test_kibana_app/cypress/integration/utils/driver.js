export const navigate = (url) => {
  cy.visit(url);
};

export const getObject = (selector) => {
  return cy.get(selector);
};

export const fillField = (selector, text) => {
  getObject(selector).clear().type(text);
  return this;
};

export const clickElement = (selector) => {
  getObject(selector).click();
  return this;
};

export const validateElementTextIncludes = (selector, text) => {
  getObject(selector).should('contain', text);
}

export const validateURLIncludes = (include) => {
  cy.url().should('include', include);
}

export const elementIsVisible = (element) => {
  return getObject(element).should('exist').should('be.visible');
}
;