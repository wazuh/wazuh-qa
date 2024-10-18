class PathManager {

    // Error Message Text
    msg = 'The selected menu does not exist.';
    // Page provides methods to interact with a single tab in a Browser
    page = null;
    // Wazuh Dashboard Root Path
    root = '/app';

    // Wazuh Dashboard Paths to Access
    options = {
        'login': this.root + '/login?', 
        'overview': this.root + '/wz-home', 
        'endpoint-summary': this.root + '/endpoints-summary',
        'agents': this.root + '/endpoints-summary#/agents?',
        'threat-hunting': this.root + '/threat-hunting#/overview/?',
        'threat-hunting-event': this.root + '/threat-hunting#/overview/?'
    };

    /**
     * Check that Option Exist
     * @param {String} option 
     * @returns {Boolean} Returns if the option is valid
     */
    check_option(option) {
        return this.options.hasOwnProperty(option);
    }

    /**
     * Throw an Error
     */
    throw_error() {
        throw new Error(this.msg);
    }

    /**
     * Class constructor
     * @param {Object} page - Page provides methods to interact with a single tab in a Browser
     */
    constructor(page) {
        this.page = page;
    }

    /**
     * Go to a specific page
     * @param {String} option 
     */
    async goto(option) {
        // Check if the option is not correct
        if (!this.check_option(option)) {
            this.throw_error();
        }

        // Go to Selected Page
        await this.page.goto(this.options[option]);
    }
  
  }
  
  module.exports = { PathManager };