const { LoginTest } = require("./tests/LoginTest.js")
const { OverviewTest } = require("./tests/OverviewTest.js")
const { EndpointTest } = require("./tests/EndpointTest.js")

async function test_login(page, vuContext) {
    await new LoginTest(page,vuContext).executeTest();
};

async function test_accessDashboard(page, vuContext) {
    await new OverviewTest(page, vuContext).executeTest();
};

async function test_accessEndpoint(page, vuContext) {
    await new EndpointTest(page, vuContext).executeTest();
};

module.exports = { 
    test_login, 
    test_accessDashboard,
    test_accessEndpoint
};