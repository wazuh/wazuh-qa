class ScreenshotManager {

    // Path where to store the screenshots
    filepath = null;
    // Screenshots Extension
    extension = `.png`;
    // Page provides methods to interact with a single tab in a Browser
    page = null;
    // User ID to group screenshots
    user_id = null;

    /**
     * Class constructor
     * @param {Object} page - Page provides methods to interact with a single tab in a Browser
     * @param {String} filepath - Path where to store the screenshots
     */
    constructor(page, filepath) {
        this.page = page;
        this.filepath = filepath;
        this.user_id = this.get_user_id();
    }

    /**
     * Get the current date and time
     * @returns {String} Returns the current date and time
     */
    get_date_and_time() {
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        const seconds = String(now.getSeconds()).padStart(2, '0');
        const milliseconds = String(now.getMilliseconds()).padStart(3, '0');
        
        return `${year}${month}${day}_${hours}${minutes}${seconds}_${milliseconds}`;
    }

    /**
     * Generate the full name of the screenshot
     * @param {String} name - Screenshot name
     * @returns {String} Returns the full name of the screenshot
     */
    get_complete_name(name) {
        return this.user_id + '-' + name + '_' + this.get_date_and_time() + this.extension;
    }

    /**
     * Generate random user id
     * @returns {String} Returns the random user id
     */
    get_user_id() {
        return Math.random().toString(36).substring(7);
    }

    /**
     * Take An Screenshot
     * @param {String} name - Screenshot name
     */
    async takeAnScreenshot(name) {
        // Generate the Complete Path to Store the Screenshots
        const full_path = this.filepath + this.get_complete_name(name);

        // Take a Browser Screenshot
        await this.page.screenshot({ path: full_path, fullPage: true });
    }
  
}

module.exports = { ScreenshotManager };