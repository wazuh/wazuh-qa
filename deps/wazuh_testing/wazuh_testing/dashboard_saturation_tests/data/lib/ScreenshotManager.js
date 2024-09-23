class ScreenshotManager {

    // Path where to store the screenshots
    filepath = null;
    // Screenshots Extension
    extension = `.png`;
    // Page provides methods to interact with a single tab in a Browser
    page = null;

    /**
     * Class constructor
     * @param {Object} page - Page provides methods to interact with a single tab in a Browser
     * @param {String} filepath - Path where to store the screenshots
     */
    constructor(page, filepath) {
        this.page = page;
        this.filepath = filepath
    }

    /**
     * Take An Screenshot
     * @param {String} name - Screenshot name
     */
    async takeAnScreenshot(name) {
        // Generate the Complete Path to Store the Screenshots
        let full_path = this.filepath + name + this.extension;

        // Take a Browser Screenshot
        await this.page.screenshot({ path: full_path, fullPage: true });
    }
  
}

module.exports = { ScreenshotManager };