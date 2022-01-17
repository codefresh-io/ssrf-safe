const { Agent: HttpAgent } = require('http');
const { Agent: HttpsAgent } = require('https');
const is_ip_private = require('private-ip');
const errorPrefix = 'SSRF:';
const patchAgent = ({
                        isPrivate = (address) => is_ip_private(address),
                        agent,
                    },
) => {
    const createConnection = agent.createConnection;
    agent.createConnection = function (options, fn) {
        const { host: address } = options;
        if (isPrivate(address)) {
            throw new Error(`${errorPrefix} private address ${address} is not allowed.`);
        }

        const client = createConnection.call(this, options, fn);
        client.on('lookup', (err, address) => {
            if (err || !isPrivate(address)) {
                return;
            }

            return client.destroy(new Error(`${errorPrefix} DNS lookup of private '${client._host}' returned ${address} is not allowed.`));
        });

        return client;
    };
    agent.PATCHED = true;
    return agent;
};


const httpAgent = patchAgent({ agent: new HttpAgent() });
const httpsAgent = patchAgent({ agent: new HttpsAgent() });

/**
 * Prepare Ssrf filter agent to use in request options as as agent.
 * The agent can be used directly by any kind of client
 * @param url
 * @param ssrf
 * @param allowListDomains
 * @param trace
 * @returns {undefined|*}
 */
const getAgent = ({ url, ssrf = true, allowListDomains = [], trace = false }) => {
    if (!ssrf) {
        return undefined;
    }
    const urlObject = new URL(url);
    const protocol = urlObject.protocol;
    const hostname = urlObject.hostname;
    if (allowListDomains.includes(hostname)) {
        trace && console.log(`Allow list match: ${hostname}, in: ${allowListDomains}, ignore ssrf`);
        return undefined;
    }
    if (protocol === 'https:') return httpsAgent;
    if (protocol === 'http:') return httpAgent;
    new Error(`${errorPrefix} Bad protocol, url must start with http/https, Got ${url}`);
};


/**
 * method for checking if an error was thrown by the Ssrf agent filter.
 * @param err
 * @returns {boolean}
 */
function isSsrfError(err) {
    return err.message.startsWith(errorPrefix);
}

module.exports = { getAgent, isSsrfError };
