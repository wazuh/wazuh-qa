const { expect } = require("@playwright/test");
const { PathManager } = require("./../lib/PathManager.js");
const { CookieManager } = require("./../lib/CookieManager.js");
const { ScreenshotManager } = require("./../lib/ScreenshotManager.js");

class EndpointTest {

    page = null;
    vuContext = null;
    pathManager = null;
    cookieManager = null;
    screenshotManager = null;

    constructor(page, vuContext) {
        this.page = page;
        this.vuContext = vuContext;
        this.pathManager = new PathManager(page);
        this.cookieManager = new CookieManager(page, vuContext.vars.username, vuContext.vars.session);
        this.screenshotManager = new ScreenshotManager(page, vuContext.vars.screenshots);
    }

    // Login with Stored Cookies
    async restoreSession() {
        await this.cookieManager.clearCookies();
        await this.cookieManager.restoreSession();
    }

    // Access the Dashboard (Endpoints)
    async accessEndpoint() {
        await this.pathManager.goto('endpoint-summary');
        await this.pathManager.waitfor('endpoint-summary');

        await this.screenshotManager.takeAnScreenshot('test_03_endpoint_summary_is_loaded');

        await expect(this.page.getByText('Endpoints')).toBeVisible();
    }

    // Check Endpoints Information
    async checkEndpointsInfo() {
        await this.screenshotManager.takeAnScreenshot('test_03_endpoint_summary_has_data');

        await expect(this.page.getByText('Status').first()).toBeVisible();
        await expect(this.page.getByText('Details')).toBeVisible();
        await expect(this.page.getByText('Evolution')).toBeVisible();
        await expect(this.page.getByText('Agents').last()).toBeVisible();
    }

    // Check Endpoints Status
    async checkEndpointsStatus() {
        await this.screenshotManager.takeAnScreenshot('test_03_endpoint_summary_has_agents');

        await expect(this.page.getByText('Active').first()).toBeVisible();
        await expect(this.page.getByText('Disconnected').first()).toBeVisible();
        await expect(this.page.getByText('Pending').first()).toBeVisible();
        await expect(this.page.getByText('Never connected').first()).toBeVisible();
    }

    // Run the Full Test
    async executeTest() {
        await this.restoreSession();
        
        await this.accessEndpoint();
        await this.checkEndpointsInfo();
        await this.checkEndpointsStatus();

        await this.page.close();
    }
  
}

module.exports = { EndpointTest };