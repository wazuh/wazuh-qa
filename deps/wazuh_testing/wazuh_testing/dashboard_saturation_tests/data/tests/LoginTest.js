const { expect } = require("@playwright/test");
const { PathManager } = require("./../lib/PathManager.js");
const { ItemManager } = require("./../lib/ItemManager.js");
const { CookieManager } = require("./../lib/CookieManager.js");
const { ScreenshotManager } = require("./../lib/ScreenshotManager.js");

class LoginTest {

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
     * Access to Login Page
     */
    async accessLogin(){
        // Go to Login Page
        await this.pathManager.goto('login');

        // Check that the Page is Loaded
        await this.itemManager.waitForText('Log in');

        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_01_login_is_loaded');
    }

    /**
     * Add User and Pass to Form
     */
    async addUserPass(){
        // Add User/Pass to the Login Form
        await this.page.getByLabel('Username').fill(this.vuContext.vars.username);
        await this.page.getByLabel('Password').fill(this.vuContext.vars.password);

        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_01_form_is_filled');
    }

    /**
     * Click on LogIn Button
     */
    async sendLogin() {
        // Click on the Login Button
        await this.page.getByText('Log in').click();
    }

    /**
     * Check that you Access the Dashboard
     */
    async checkLogin() {
        // Wait for the Overview Page to Load
        await this.itemManager.waitForOverview();

        // Take a Browser Screenshot
        await this.screenshotManager.takeAnScreenshot('test_01_overview_is_loaded');
    }

    /**
     * Run the Full Test
     */
    async executeTest() {
        // Run the Tests
        await this.accessLogin();
        await this.addUserPass();
        await this.sendLogin();
        await this.checkLogin();
        
        // Save the Cookie in the Session File
        await this.cookieManager.saveSession();

        // Close the Browser
        await this.page.close();
    }
  
}

module.exports = { LoginTest };