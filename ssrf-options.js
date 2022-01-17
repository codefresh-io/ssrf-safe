/******************************
 * Convenience methods
 */

const { getAgent } = require('./ssrf-filter');

/**
 * method returning options with agent based on url parameter
 */
function ssrfOptions({ url, options = {}, trace = true, allowListDomains = [] }) {
    const agent = getAgent({ url, allowListDomains });
    return { ...options, agent };
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
                                trace = false,  // for test/debug
                                allowListDomains = [], //
                            }) {
    url = url || options.uri;
    options = ssrfOptions({ url: url, options, trace, allowListDomains });
    return { ...options, uri: url };
}


module.exports = { requestSsrfOptions };
