const { expect } = require("@playwright/test");
const { PathManager } = require("./../lib/PathManager.js");
const { ItemManager } = require("./../lib/ItemManager.js");
const { CookieManager } = require("./../lib/CookieManager.js");
const { ScreenshotManager } = require("./../lib/ScreenshotManager.js");

class EndpointTest {

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
     * Access the Dashboard (Endpoints)
     */
    async accessEndpoint() {
        // Go to Endpoint Section
        await this.pathManager.goto('endpoint-summary');

        // Check that the Page has Loaded Correctly
        await this.itemManager.waitForEndpointSummary();

        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_03_endpoint_summary_is_loaded');
    }

    /**
     * Check Endpoints Status
     */
    async checkEndpointsStatus() {
        // Check that the Status on the Endpoints Page Appears
        await this.itemManager.waitForAgentStatus()

        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_03_endpoint_summary_has_statuses');
    }

    /**
     * Check Info about Agents
     */
    async checkAgentInfo() {
        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_03_endpoint_summary_has_agents');

        // Check that the Status on the Endpoints Page Appears
        await this.itemManager.waitForAgentInfo()        
    }

    /**
     * Run the Full Test
     */
    async executeTest() {
        // Restore Browser Session
        await this.restoreSession();
        
        // Run the Tests
        await this.accessEndpoint();
        await this.checkEndpointsStatus();
        await this.checkAgentInfo();

        // Close the Browser
        await this.page.close();
    }
  
}

module.exports = { EndpointTest };