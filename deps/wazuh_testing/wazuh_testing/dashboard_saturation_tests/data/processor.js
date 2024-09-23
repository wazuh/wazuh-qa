const { LoginTest } = require("./tests/LoginTest.js")
const { OverviewTest } = require("./tests/OverviewTest.js")
const { EndpointTest } = require("./tests/EndpointTest.js")
const { EventTest } = require("./tests/EventTest.js")

/**
 * Function to run login tests
 * @param {Object} page - Page provides methods to interact with a single tab in a Browser
 * @param {Object} vuContext - Virtual user context and events arguments
 */
async function test_login(page, vuContext) {
    await new LoginTest(page,vuContext).executeTest();
};

/**
 * Function to run dashboard tests
 * @param {Object} page - Page provides methods to interact with a single tab in a Browser
 * @param {Object} vuContext - Virtual user context and events arguments
 */
async function test_accessDashboard(page, vuContext) {
    await new OverviewTest(page, vuContext).executeTest();
};

/**
 * Function to run endpoint tests
 * @param {Object} page - Page provides methods to interact with a single tab in a Browser
 * @param {Object} vuContext - Virtual user context and events arguments
 */
async function test_accessEndpoint(page, vuContext) {
    await new EndpointTest(page, vuContext).executeTest();
};

/**
 * Function to run event tests
 * @param {Object} page - Page provides methods to interact with a single tab in a Browser
 * @param {Object} vuContext - Virtual user context and events arguments
 */
async function test_accessEvent(page, vuContext) {
    await new EventTest(page, vuContext).executeTest();
};

module.exports = { 
    test_login, 
    test_accessDashboard,
    test_accessEndpoint,
    test_accessEvent
};