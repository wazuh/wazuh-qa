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
        this.filepath = filepath;
    }

    /**
     * Get the current date and time
     * @returns {String} Returns the current date and time
     */
    get_date_and_time() {
        date_and_time =  Date().toLocaleString(
            'es-ES',
            {
                year: 'numeric', 
                month: '2-digit', 
                day: '2-digit',
                hour: '2-digit', 
                minute: '2-digit', 
                second: '2-digit',
                fractionalSecondDigits: 3
            }
        );

        return date_and_time.replace(',', '-');
    }

    /**
     * Generate the full name of the screenshot
     * @param {String} name - Screenshot name
     * @returns {String} Returns the full name of the screenshot
     */
    get_complete_name(name) {
        return this.get_date_and_time() + '-' + name + this.extension;
    }

    /**
     * Take An Screenshot
     * @param {String} name - Screenshot name
     */
    async takeAnScreenshot(name) {
        // Generate the Complete Path to Store the Screenshots
        let full_path = this.filepath + this.get_complete_name(name);

        // Take a Browser Screenshot
        await this.page.screenshot({ path: full_path, fullPage: true });
    }
  
}

module.exports = { ScreenshotManager };