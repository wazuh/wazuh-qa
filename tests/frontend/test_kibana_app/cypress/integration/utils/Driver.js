class Driver {

    static navigate(url) {
        cy.visit(url);
    }

    static getObject(selector) {
        return cy.get(selector);
    }

    static fillField(selector, text) {
        this.getObject(selector)
            .clear()
            .type(text);
        return this;
    }

    static clickElement(selector) {
        this.getObject(selector)
            .click();
        return this;
    }

    static elementIsVisible(element) {
        return this.getObject(element)
            .should('exist')
            .should('be.visible');
    }
}

export default Driver;
