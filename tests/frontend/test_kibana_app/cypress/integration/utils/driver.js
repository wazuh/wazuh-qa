export const clickElement = (selector) => {
  getElement(selector).click();
  return this;
};

export const getAttributeElement = (selector) => {
  return getElement(selector).invoke('attr', 'aria-checked').then(($element) => {
    const value = $element
    return value;
  });
};

export const elementIsNotVisible = (selector) => {
  return getElement(selector).should('not.exist');
};

export const elementIsVisible = (selector) => {
  return getElement(selector).should('exist').should('be.visible');
};

export const elementTextIncludes = (selector, text) => {
  getElement(selector).should('contain', text);
};

export const fillField = (selector, text) => {
  getElement(selector).clear().type(text);
  return this;
};

export const fillSelectorField = (selector, text) => {
  getElement(selector).type(text);
  return this;
};

export const getElement = (selector) => {
  return cy.get(selector);
};

export const interceptAs = (methodUsed, urlUsed, alias) => {
  cy.intercept({
    method: methodUsed,
    url: urlUsed
  }).as(alias);
};

export const navigate = (url) => {
  cy.visit(url);
};

export const validateURLIncludes = (include) => {
  cy.url().should('include', include);
};

export const clearSession = () => {
  cy.clearLocalStorage();
  cy.clearCookies();
};

export const setCookies = (cookieObj) => {
  try {
  cookieObj.forEach((element) => {
    cy.setCookie(element.name, element.value);
  });
} catch (e) {
}
}

export const updateCookies = () => {
  const filename = 'cookie.json';
  cy.getCookies().then((currentCook) => {
    const parameterToFilter = ['sid', 'wz-token'];
    for (let l = 0; l < parameterToFilter.length; l++) {
      const [cookie] = currentCook.filter(e => e.name == parameterToFilter[l]);
      // const newCookies = obj.map(e => {
      //   //ver cookie.value
      //   if (e.name == parameterToFilter[l]) e.value = cookie.value
      //   return e;
      cy.readFile(filename).then((obj) => {

        const newCookie = obj.map(e => {
        if (e.name == parameterToFilter[l]) e.value = cookie.value
        return e;
        })
        cy.writeFile(filename,  JSON.stringify(newCookie))

      })
    }
  });
}

export const updateExpiryValueCookies =  () => {
  let timestamp = new Date().getTime();
  let today = new Date();
  const filename = 'cookie.json';
  try {
    cy.readFile(filename).then((obj) => {
      const newCookie = obj.map(e => { 
        let oldDate = new Date(e.expiry);
        if (oldDate < today) e.expiry = timestamp;
        return e;
      })
      cy.writeFile(filename, JSON.stringify(newCookie))
    })
  } catch (e) {
  }
}

export const getMyCookie = () => {
  let cookie;
  return cy.getCookie().then((c) => {
    return cookie = c;
  })
}
// Function that's return the selector by xpath
export const xPathSelector = (selector) => {
  return cy.xpath(selector);
}
export const clickXpathElement = (selector) => {
  xPathSelector(selector).click();
  return this;
};
export const elementXpathIsVisible = (selector) => {
  return xPathSelector(selector).should('exist').should('be.visible');
};