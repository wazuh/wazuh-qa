const { expect } = require("@playwright/test");
const { PathManager } = require("./../lib/PathManager.js");
const { CookieManager } = require("./../lib/CookieManager.js");
const { ScreenshotManager } = require("./../lib/ScreenshotManager.js");

class EventTest {

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
    async accessEventTab() {
        // Go to Endpoint Summary Page
        await this.pathManager.goto('endpoint-summary');
        await this.pathManager.waitfor('endpoint-summary');

        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_04_endpoint_summary_is_loaded');

        // Check that the Page is Loaded
        await expect(this.page.getByText('Endpoints')).toBeVisible();
    }

    /**
     * Access the Agent Section
     */
    async accessAgent() {
        // Click on an Agent
        await this.page.getByText('001').click();
        await this.pathManager.waitfor('agents');

        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_04_agent_section_is_loaded');
    }

    /**
     * Access the Alerts Section
     */
    async accessAlerts() {
        // Check that the Threat Hunting Section has been Accessed
        await this.page.getByText('Threat Hunting ').click();
        await this.pathManager.waitfor('threat-hunting');

        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_04_threat_hunting_is_loaded');
    }

    /**
     * Check Events in the Table
     */
    async checkEvents() {
        // Click on Events Tab
        await this.page.getByText('Events').click();
        await this.pathManager.waitfor('threat-hunting-event');

        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_04_events_tab_is_loaded');

        // Check that the Event Table has been Loaded
        expect(await this.page.getByLabel('tr').count()).toBeGreaterThanOrEqual(1);
    }

    /**
     * Run the Full Test
     */
    async executeTest() {
        // Restore Browser Session
        await this.restoreSession();
        
        // Run the Tests
        await this.accessEventTab();
        await this.accessAgent();
        await this.accessAlerts();
        await this.checkEvents();

        // Close the Browser
        await this.page.close();
    }

}

module.exports = { EventTest };