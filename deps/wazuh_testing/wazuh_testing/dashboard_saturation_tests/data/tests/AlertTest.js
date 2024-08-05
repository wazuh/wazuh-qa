const { expect } = require("@playwright/test");
const { PathManager } = require("./../lib/PathManager.js");
const { CookieManager } = require("./../lib/CookieManager.js");
const { ScreenshotManager } = require("./../lib/ScreenshotManager.js");

class AlertTest {

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

        await this.screenshotManager.takeAnScreenshot('test_04_endpoint_summary_is_loaded');

        await expect(this.page.getByText('Endpoints')).toBeVisible();
    }

    // Access the Agent Section
    async accessAgent() {
        await this.page.getByText('001').click();
        await this.pathManager.waitfor('agent');

        await this.screenshotManager.takeAnScreenshot('test_04_agent_section_is_loaded');
    }

    // Access the Alerts Section
    async accessAlerts() {
        await this.page.getByText('Threat Hunting ').click();
        await this.pathManager.waitfor('threat-hunting');

        await this.screenshotManager.takeAnScreenshot('test_04_threat_hunting_is_loaded');
    }

    async checkEvents() {
        await this.page.getByText('Events').click();

        await expect(this.page.getByLabel('td').count()).toBeGreaterThanOrEqual(1);
    }

    // Run the Full Test
    async executeTest() {
        await this.restoreSession();
        
        this.accessEndpoint();
        //this.accessAgent();
        //this.accessAlerts();
        //this.checkEvents();

        await this.page.close();
    }
  
}

module.exports = { AlertTest };