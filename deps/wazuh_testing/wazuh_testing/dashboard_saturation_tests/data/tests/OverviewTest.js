const { expect } = require("@playwright/test");
const { PathManager } = require("./../lib/PathManager.js");
const { CookieManager } = require("./../lib/CookieManager.js");
const { ScreenshotManager } = require("./../lib/ScreenshotManager.js");

class OverviewTest {

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
     * Access the Dashboard (Overview)
     */
    async accessOverview() {
        // Go to Overview Section
        await this.pathManager.goto('overview');
        await this.pathManager.waitfor('overview');

        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_02_overview_is_loaded');
        
        // Check that the Overview Page is Loaded
        await expect(this.page.getByText('Overview')).toBeVisible();
    }

    /**
     * Check Overview Information
     */
    async checkOverviewInfo() {
        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_02_overview_dashboard');

        // Check that the Overview Information Appears
        await expect(this.page.getByTitle('Agents Summary')).toBeVisible();
        await expect(this.page.getByTitle('Last 24 hours alerts')).toBeVisible();
        await expect(this.page.getByTitle('Endpoint security')).toBeVisible();
        await expect(this.page.getByTitle('Threat intelligence')).toBeVisible();
        await expect(this.page.getByTitle('Security operations')).toBeVisible();
        await expect(this.page.getByTitle('Cloud security')).toBeVisible();
    }

    /**
     * Run the Full Test
     */
    async executeTest() {
        // Restore Browser Session
        await this.restoreSession();
        
        // Run the Tests
        await this.accessOverview();
        await this.checkOverviewInfo();

        // Close the Browser
        await this.page.close();
    }
  
}

module.exports = { OverviewTest };