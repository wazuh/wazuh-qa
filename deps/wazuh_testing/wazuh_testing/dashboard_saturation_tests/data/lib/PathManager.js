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

    // Wazuh Dashboard Requests to Wait for to Ensure It is Loaded
    requests = {
        'login': '/ui/logos/wazuh_dashboard_login_background.svg', 
        'overview': '/bundles/plugin/data/data.chunk.5.js',
        'endpoint-summary': '/bundles/plugin/wazuh/0317d582b93c20f68e059e389aecab33.woff2',
        'agents': '/bundles/plugin/visTypeVislib/visTypeVislib.chunk.2.js',
        'threat-hunting': '/elastic/samplealerts',
        'threat-hunting-event': '/ui/logos/opensearch_mark_on_light.svg'
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
     * Check that Request Exist
     * @param {String} request 
     * @returns {Boolean} Returns if the request is valid
     */
    check_request(request) {
        return this.requests.hasOwnProperty(request);
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

    /**
     * Wait for a page to load
     * @param {String} request 
     */
    async waitfor(request) {
        // Check if the request is not correct
        if (!this.check_request(request)) {
            this.throw_error();
        }

        // If the Request is not Login, Wait for the Dashboard URL to Load
        if ('login' != request) {
            await this.page.waitForURL('**' + this.options[request] + '**');
        }

        // Wait for the Request to Load
        await this.page.waitForResponse(response => response.url().includes(this.requests[request]));
    }

  
  }
  
  module.exports = { PathManager };