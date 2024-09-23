const fs = require('fs');

class CookieManager {

    // Page provides methods to interact with a single tab in a Browser
    page = null;
    // Wazuh dashboard username
    username = null;
    // Cookie storage path
    filename = null;

    /**
     * Class constructor
     * @param {Object} page - Page provides methods to interact with a single tab in a Browser
     * @param {String} username - Wazuh dashboard username
     * @param {String} session - Cookie storage path
     */
    constructor(page, username, session) {
        this.page = page;
        this.username = username;
        this.filename = `${session}user-${username}.json`;
    }

    /**
     * Clear Browser Cookies
     */
    async clearCookies() {
        await this.page.context().clearCookies();
    }

    /**
     * Saving Cookies to an External File
     */
    async saveSession() {
        await this.page.context().storageState({ path: this.filename });
    }

    /**
     * Convert External File with Cookies to JSON
     * @returns {Object} JSON object
     */
    getSavedSession() {
        return JSON.parse(fs.readFileSync(this.filename));
    }

    /**
     * Recover Cookies from External File
     * @returns {Object} JSON Object
     */
    getCookies() {
        return this.getSavedSession().cookies;
    }
    
    /**
     * Use Stored Cookies for Login
     */
    async restoreSession() {
        await this.page.context().addCookies(this.getCookies());
    }
  
}

module.exports = { CookieManager };