const { expect } = require("@playwright/test");
const { PathManager } = require("./../lib/PathManager.js");
const { CookieManager } = require("./../lib/CookieManager.js");
const { ScreenshotManager } = require("./../lib/ScreenshotManager.js");

class LoginTest {

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
  
    // Access to Login Page
    async accessLogin(){
        await this.pathManager.goto('login');
        await this.pathManager.waitfor('login');

        await this.screenshotManager.takeAnScreenshot('test_01_login_is_loaded');

        await expect(this.page.getByText('Log In')).toBeVisible();
    }

    // Add User and Pass to Form
    async addUserPass(){
        await this.page.getByLabel('Username').fill(this.vuContext.vars.username);
        await this.page.getByLabel('Password').fill(this.vuContext.vars.password);

        await this.screenshotManager.takeAnScreenshot('test_01_form_is_filled');
    }

    // Click on LogIn Button
    async sendLogin() {
        await this.page.getByText('Log in').click();
    }

    // Check that you Access the Dashboard
    async checkLogin() {
        await this.pathManager.waitfor('overview');

        await this.screenshotManager.takeAnScreenshot('test_01_overview_is_loaded');

        await expect(this.page.getByText('Overview')).toBeVisible();
    }

    // Run the Full Test
    async executeTest() {
        await this.accessLogin();
        await this.addUserPass();
        await this.sendLogin();
        await this.checkLogin();
        
        await this.cookieManager.saveSession();
        await this.page.close();
    }
  
}

module.exports = { LoginTest };