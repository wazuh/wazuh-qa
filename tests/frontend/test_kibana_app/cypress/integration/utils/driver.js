/// <reference types="cypress" />
export const clickElement = (selector) => {
  getElement(selector).should('not.be.disabled').click();
  return this;
};

export const forceClickElement = (selector) => {
  cy.wait(1000);
  getElement(selector).click({force:true})
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

export const cleanAndfillField = (selector, text) => {
  getElement(selector).clear().type(text);
  return this;
};

export const fillField = (selector, text) => {
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

export const setCookies = (cookieFromFile) => {
  try {
    cy.getCookies().then((currentCookie) => {
      if (currentCookie.length != 0) {
        cookieFromFile.forEach((element) => {
          cy.setCookie(element.name, element.value);
        });
      }else{
        cy.readFile('cookie.json').then((cookieFile) => {
          cy.log('cookie',cookieFile);
            cookieFile.forEach(element => { 
            cy.setCookie(element.name, element.value);
          })
        })
      }
    });
  } catch (e) {
  }
}

export const updateCookies = () => {
  const filename = 'cookie.json';
  cy.getCookies().then((currentCook) => {
     if(currentCook.length != 0){
    const parameterToFilter = ['sid', 'wz-token'];
    for (let l = 0; l < parameterToFilter.length; l++) {
      const [cookie] = currentCook.filter(e => e.name == parameterToFilter[l]);
      cy.readFile(filename).then((obj) => {
        const newCookie = obj.map(e => {
        if (e.name == parameterToFilter[l]) e.value = cookie.value
        return e;
        })
        cy.writeFile(filename,  JSON.stringify(newCookie))
      })
    }
   }
  });
}

export const preserveCookie = () => {
  let str = [];
 return cy.getCookies().then((cook) => {
      if(cook.length != 0){
      for (let l = 0; l < cook.length; l++) {
          if (cook.length > 0 && l == 0) {
              str[l] = cook[l].name;
              Cypress.Cookies.preserveOnce(str[l]);
          }
          else if (cook.length > 1 && l > 1) {
              str[l] = cook[l].name;
              Cypress.Cookies.preserveOnce(str[l]);
          }
      }
    }
  })
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

// Function that's return the selector by xpath
export const getXpathElement = (selector) => {
  return cy.xpath(selector);
}
export const clickXpathElement = (selector) => {
  getXpathElement(selector).click();
  return this;
};
export const xpathElementIsVisible = (selector) => {
  return getXpathElement(selector).should('exist').should('be.visible');
};
export const timestampToDate = (e) => {
  let newDates = e.getDate()+"/"+(e.getMonth()+1)+"/"+e.getFullYear()+" "+e.getHours()+":"+e.getMinutes()+":"+e.getSeconds();
  return newDates;
};
