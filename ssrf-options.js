/******************************
 * Convenience methods
 */

const { getAgent } = require('./ssrf-filter');

/**
 * method returning options with agent based on url parameter
 */
function ssrfOptions({ url, options = {}, callLog = undefined, allowListDomains = [] }) {
    const agent = getAgent({ url, allowListDomains, callLog });
    return { ...options, agent, callLog };
}

/**
 * convenience method for creating request options.
 * returning request options with agent for ssrf safe requests.
 * for enriching options with ssrf agent filter,
 * '.uri' is required in options or provided as 'url' explicitly
 */
function requestSsrfOptions({
                                url = undefined,
                                options = { uri: undefined },
                                callLog = undefined,  // for log/test/debug
                                allowListDomains = [], //
                            }) {
    url = url || options.uri;
    options = ssrfOptions({ url: url, options, callLog, allowListDomains });
    return { ...options, uri: url };
}


module.exports = { requestSsrfOptions };
