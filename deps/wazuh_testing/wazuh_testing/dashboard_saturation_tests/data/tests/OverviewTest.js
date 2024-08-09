const { expect } = require("@playwright/test");
const { PathManager } = require("./../lib/PathManager.js");
const { CookieManager } = require("./../lib/CookieManager.js");
const { ScreenshotManager } = require("./../lib/ScreenshotManager.js");

class OverviewTest {

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

    // Access the Dashboard (Overview)
    async accessOverview() {
        await this.pathManager.goto('overview');
        await this.pathManager.waitfor('overview');

        await this.screenshotManager.takeAnScreenshot('test_02_overview_is_loaded');
        
        await expect(this.page.getByText('Overview')).toBeVisible();
    }

    // Check Overview Information
    async checkOverviewInfo() {
        await this.screenshotManager.takeAnScreenshot('test_02_overview_dashboard');

        await expect(this.page.getByTitle('Agents Summary')).toBeVisible();
        await expect(this.page.getByTitle('Last 24 hours alerts')).toBeVisible();
        await expect(this.page.getByTitle('Endpoint security')).toBeVisible();
        await expect(this.page.getByTitle('Threat intelligence')).toBeVisible();
        await expect(this.page.getByTitle('Security operations')).toBeVisible();
        await expect(this.page.getByTitle('Cloud security')).toBeVisible();
    }

    // Run the Full Test
    async executeTest() {
        await this.restoreSession();
        
        await this.accessOverview();
        await this.checkOverviewInfo();

        await this.page.close();
    }
  
}

module.exports = { OverviewTest };