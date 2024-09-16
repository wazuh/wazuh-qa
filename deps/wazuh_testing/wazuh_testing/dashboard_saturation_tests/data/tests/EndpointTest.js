const { expect } = require("@playwright/test");
const { PathManager } = require("./../lib/PathManager.js");
const { CookieManager } = require("./../lib/CookieManager.js");
const { ScreenshotManager } = require("./../lib/ScreenshotManager.js");

class EndpointTest {

    // Page provides methods to interact with a single tab in a Browser
    page = null;
    // Virtual user context and events arguments
    vuContext = null;
    // PathManager Instance
    pathManager = null;
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
        await this.pathManager.waitfor('endpoint-summary');

        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_03_endpoint_summary_is_loaded');

        // Check that the Page has Loaded Correctly
        await expect(this.page.getByText('Endpoints')).toBeVisible();
    }

    /**
     * Check Endpoints Information
     */
    async checkEndpointsInfo() {
        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_03_endpoint_summary_has_data');

        // Check that the Information on the Endpoints Page Appears
        await expect(this.page.getByText('Status').first()).toBeVisible();
        await expect(this.page.getByText('Details')).toBeVisible();
        await expect(this.page.getByText('Evolution')).toBeVisible();
        await expect(this.page.getByText('Agents').last()).toBeVisible();
    }

    /**
     * Check Endpoints Status
     */
    async checkEndpointsStatus() {
        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_03_endpoint_summary_has_agents');

        // Check that the Status on the Endpoints Page Appears
        await expect(this.page.getByText('Active').first()).toBeVisible();
        await expect(this.page.getByText('Disconnected').first()).toBeVisible();
        await expect(this.page.getByText('Pending').first()).toBeVisible();
        await expect(this.page.getByText('Never connected').first()).toBeVisible();
    }

    /**
     * Run the Full Test
     */
    async executeTest() {
        // Restore Browser Session
        await this.restoreSession();
        
        // Run the Tests
        await this.accessEndpoint();
        await this.checkEndpointsInfo();
        await this.checkEndpointsStatus();

        // Close the Browser
        await this.page.close();
    }
  
}

module.exports = { EndpointTest };