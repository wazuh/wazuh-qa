const { expect } = require("@playwright/test");
const { PathManager } = require("./../lib/PathManager.js");
const { ItemManager } = require("./../lib/ItemManager.js");
const { CookieManager } = require("./../lib/CookieManager.js");
const { ScreenshotManager } = require("./../lib/ScreenshotManager.js");

class OverviewTest {

    // Page provides methods to interact with a single tab in a Browser
    page = null;
    // Virtual user context and events arguments
    vuContext = null;
    // PathManager Instance
    pathManager = null;
    // ItemManager Instance
    itemManager = null;
    // CookieManager Instance
    cookieManager = null;
    // ScreenshotManager Instance
    screenshotManager = null;

    /**
     * Function to run event tests
     * @param {Object} page - Page provides methods to interact with a single tab in a Browser
     * @param {Object} vuContext - Virtual user context and events arguments
     */
    constructor(page, vuContext) {
        this.page = page;
        this.vuContext = vuContext;
        this.pathManager = new PathManager(page);
        this.itemManager = new ItemManager(page, vuContext.vars.timeout);
        this.cookieManager = new CookieManager(page, vuContext.vars.username, vuContext.vars.session);
        this.screenshotManager = new ScreenshotManager(page, vuContext.vars.screenshots);
    }

    /**
     * Login with Stored Cookies
     */
    async restoreSession() {
        // Clear Browser Cookies
        await this.cookieManager.clearCookies();
        
        // Restore Browser Cookies
        await this.cookieManager.restoreSession();
    }

    /**
     * Access the Dashboard (Overview) and check information
     */
    async accessOverview() {
        // Go to Overview Section
        await this.pathManager.goto('overview');

        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_02_overview_is_loaded');

        // Check that the Page is Loaded
        await this.itemManager.waitForOverview();

        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_02_overview_dashboard');
    }

    /**
     * Run the full test
     */
    async executeTest() {
        // Restore Browser Session
        await this.restoreSession();
        
        // Run the Tests
        await this.accessOverview();

        // Close the Browser
        await this.page.close();
    }
  
}

module.exports = { OverviewTest };