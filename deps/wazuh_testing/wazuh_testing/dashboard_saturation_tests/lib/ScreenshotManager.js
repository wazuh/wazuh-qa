class ScreenshotManager {

    filepath = null;
    extension = `.png`;
    page = null;

    constructor(page, filepath) {
        this.page = page;
        this.filepath = filepath
    }

    // Take An Screenshot
    async takeAnScreenshot(name) {
        let full_path = this.filepath + name + this.extension;

        await this.page.screenshot({ path: full_path, fullPage: true });
    }
  
}

module.exports = { ScreenshotManager };