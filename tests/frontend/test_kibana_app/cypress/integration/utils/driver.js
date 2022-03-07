export const clickElement = (selector) => {
  getElement(selector).click();
  return this;
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
  cookieObj.forEach((element) => {
    cy.setCookie(element.name, element.value);
  });

}

export const updateCookies = (parameterToFilter) => {
  const filename = 'cookie.json';
  cy.getCookies().then((currentCook) => {
    const [cookie] = currentCook.filter(e => e.name == parameterToFilter);
    // const newCookies = cookieMock.map(e => {
    //   //ver cookie.value
    //   if (e.name == parameterToFilter) e.value = cookie.value;
    //   return e;
    debugger
    cy.readFile(filename).then((obj) => {
  
      obj.forEach(e => {
        debugger
        if(e.name == parameterToFilter) e.value = cookie.value
      })
      cy.writeFile(filename, obj)

    })
    // })
    
   cy.log(`cookie: ${currentCook}`);
  });
}

export const writeFiles = async (cookie) => {
  const filename = 'cookie.json';
  cy.readFile(filename).then((list) => {
    list.push(cookie)
    // escribe el objeto fusionado
    cy.writeFile(filename, list)
  })
}

export const getMyCookie = () => {
  let cookie;
  return cy.getCookie().then((c) => {
    return cookie = c;
  })
}