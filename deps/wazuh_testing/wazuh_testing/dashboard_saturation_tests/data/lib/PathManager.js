class PathManager {

    msg = 'The selected menu does not exist.';
    page = null;
    root = '/app';

    options = {
        'login': this.root + '/login?', 
        'overview': this.root + '/wz-home', 
        'endpoint-summary': this.root + '/endpoints-summary',
        'agents': this.root + '/endpoints-summary#/agents?',
        'threat-hunting': this.root + '/threat-hunting#/overview/?',
        'threat-hunting-event': this.root + '/threat-hunting#/overview/?'
    };

    requests = {
        'login': '/ui/logos/wazuh_dashboard_login_background.svg', 
        'overview': '/bundles/plugin/data/data.chunk.5.js',
        'endpoint-summary': '/bundles/plugin/wazuh/0317d582b93c20f68e059e389aecab33.woff2',
        'agents': '/bundles/plugin/visTypeVislib/visTypeVislib.chunk.2.js',
        'threat-hunting': '/elastic/samplealerts',
        'threat-hunting-event': '/ui/logos/opensearch_mark_on_light.svg'
    };

    // Check that Menu Exist
    check_option(option) {
        return this.options.hasOwnProperty(option);
    }

    // Check that Menu Exist
    check_request(request) {
        return this.requests.hasOwnProperty(request);
    }

    // Throw an Error
    throw_error() {
        throw new Error(this.msg);
    }

    constructor(page) {
        this.page = page;
    }

    // Go To
    async goto(option) {
        if (!this.check_option(option)) {
            this.throw_error();
        }

        await this.page.goto(this.options[option]);
    }

    // Wait For
    async waitfor(request) {
        if (!this.check_request(request)) {
            this.throw_error();
        }

        if ('login' != request) {
            await this.page.waitForURL('**' + this.options[request] + '**');
        }

        await this.page.waitForResponse(response => response.url().includes(this.requests[request]));
    }

  
  }
  
  module.exports = { PathManager };