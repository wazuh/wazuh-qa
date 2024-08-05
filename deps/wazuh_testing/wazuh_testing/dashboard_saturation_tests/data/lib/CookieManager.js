const fs = require('fs');

class CookieManager {

    page = null;
    username = null;
    filename = null;

    constructor(page, username, session) {
        this.page = page;
        this.username = username;
        this.filename = `${session}user-${username}.json`;
    }

    // Clear Cookies
    async clearCookies() {
        await this.page.context().clearCookies();
    }

    // Saving Cookies to an External File
    async saveSession() {
        await this.page.context().storageState({ path: this.filename });
    }

    // Convert External File with Cookies to JSON
    getSavedSession() {
        return JSON.parse(fs.readFileSync(this.filename));
    }

    // Recover Cookies from External File
    getCookies() {
        return this.getSavedSession().cookies;
    }
    
    // Use Stored Cookies for Login
    async restoreSession() {
        await this.page.context().addCookies(this.getCookies());
    }
  
}

module.exports = { CookieManager };