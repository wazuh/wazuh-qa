const navigate = (url) => {
  cy.visit(url);
};

const getObject = (selector) => {
  return cy.get(selector);
};

const fillField = (selector, text) => {
  getObject(selector).clear().type(text);
  return this;
};

const clickElement = (selector) => {
  getObject(selector).click();
  return this;
};

const elementIsVisible = (element) => {
  return getObject(element).should('exist').should('be.visible');
};

export { navigate, getObject, fillField, clickElement, elementIsVisible };
