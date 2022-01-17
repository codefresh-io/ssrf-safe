
/******************************
 * Convenience methods
 */

const http = require('http');
const request = require('request-promise');
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
                                ssrf = true,    // for test/debug
                                allowListDomains = [], //
                            }) {
    url = url || options.uri;
    options = ssrf ? ssrfOptions({ url: url, options, trace, allowListDomains }) : options;
    return { ...options, uri: url };
}

/**
 * Native node http lib use of ssrf agent
 */
async function httpSsrfGet({ url, trace = true, ssrf = false, allowListDomains = [] }) {
    trace && console.log(`Calling ${url} ssrf:${ssrf} allowListDomains:${allowListDomains}`);
    const options = {
        agent: getAgent({ url, ssrf, allowListDomains, trace }),
    };
    const waitfor = new Promise((resolve, reject) => {
        let data = [];
        trace && console.log(`http.get ${url},  ${JSON.stringify(options)}`);
        http.get(url, options, res => {
            const headerDate = res.headers && res.headers.date ? res.headers.date : 'no response date';
            trace && console.log('Status Code:', res.statusCode);
            trace && console.log('Date in Response header:', headerDate);

            res.on('data', chunk => {
                data.push(chunk);
            });

            res.on('end', () => {
                trace && console.log('Response ended: ');
                resolve({ data: data.join(''), statusCode: res.statusCode });
            });
        })
            .on('error', err => {
                trace && console.log('Error: ', err.message);
                reject(err);
            });
    });
    const result = await waitfor;
    trace && console.log(`Called ${url} return ${JSON.stringify(result)}`);
    return result;
}

/**
 * convenience method for doing request get.
 * @param url
 * @param trace
 * @param ssrf
 * @param allowListDomains
 * @returns {Promise<*>}
 */
async function requestSsrfGet({ url, trace = true, ssrf = true, allowListDomains = [] }) {
    trace && console.log(`requestGet Calling ${url} ssrf: ${ssrf} allowListDomains:${allowListDomains}`);
    const options = requestSsrfOptions({ url, trace, ssrf, allowListDomains });
    try {
        const result = await request(options);
        trace && console.log(`requestGet Called ${url} return ${JSON.stringify(result)}`);
        return result;
    } catch (err) {
        trace && console.log('Error: ', err.message);
        throw err;
    }
}


module.exports = { requestSsrfOptions, requestSsrfGet, httpSsrfGet };
