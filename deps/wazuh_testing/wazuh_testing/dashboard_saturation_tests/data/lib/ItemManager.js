class ItemManager {

    // Page provides methods to interact with a single tab in a Browser
    page = null;

    // Timeout defines the maximum waiting time in milliseconds
    timeout = null;

    /**
     * Class constructor
     * @param {Object} page - Page provides methods to interact with a single tab in a Browser
     */
    constructor(page, timeout) {
        this.page = page;
        this.timeout = timeout;
    }

    /**
     * Wait for the text to appear on the dashboard
     * @param {String} dashboard_text 
     */
    async waitForText(dashboard_text) {
        // Function to wait for a certain text to appear
        await this.page.waitForSelector(`text=${dashboard_text}`, { state: 'visible', timeout: this.timeout });
    }

    /**
     * Wait for Overview to load completely
     */
    async waitForOverview() {
        // Function to wait for a certain text to appear
        await this.waitForText('Overview')
        await this.waitForText('Agents summary')
        await this.waitForText('Last 24 hours alerts')
        await this.waitForText('Endpoint security');
        await this.waitForText('Threat intelligence');
        await this.waitForText('Security operations');
        await this.waitForText('Cloud security');
    }

    /**
     * Wait for Endpoint Summary to load completely
     */
    async waitForEndpointSummary() {
        // Function to wait for a certain text to appear
        await this.waitForText('Endpoints')
        await this.waitForText('Agents by Status')
        await this.waitForText('Top 5 OS')
        await this.waitForText('Top 5 groups');
        await this.waitForText('Agents');
    }

    /**
     * Wait for Endpoint Summary (Agent Status) to load completely
     */
    async waitForAgentStatus() {
        // Function to wait for a certain text to appear
        await this.waitForText('Active')
        await this.waitForText('Disconnected')
        await this.waitForText('Pending');
        await this.waitForText('Never connected');
    }

    /**
     * Wait for Endpoint Summary (Agent Info) to load completely
     */
    async waitForAgentStatus() {
        // Function to wait for a certain text to appear
        await this.waitForText('ID')
        await this.waitForText('Name')
        await this.waitForText('Version');
        await this.waitForText('Status');
    }

}

module.exports = { ItemManager };