const assertLib = require('assert');
const assert = assertLib.strict;

const http = require('http');
const request = require('request-promise');
const { getAgent } = require('./ssrf-filter');
const { requestSsrfOptions, isSsrfError } = require('./index');

/*******
 * Test Helper methods
 */

/**
 * Native node http lib use of ssrf agent
 */
async function httpSsrfGet({ url, trace = true, ssrf = false, allowListDomains = [] }) {
    trace && console.log(`Calling ${url} ssrf:${ssrf} allowListDomains:${allowListDomains}`);
    const options = ssrf ? {
        agent: getAgent({ url, allowListDomains, trace }),
    } : {};
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
    const options = ssrf ? requestSsrfOptions({ url, trace, ssrf, allowListDomains }) : { uri: url };
    try {
        const result = await request(options);
        trace && console.log(`requestGet Called ${url} return ${JSON.stringify(result)}`);
        return result;
    } catch (err) {
        trace && console.log('Error: ', err.message);
        throw err;
    }
}

/*********
 * Test server
 */

const server = http.createServer(function (req, res) {
    const url = req.url;

    if (url === '/') {
        // do a 200 response
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.write('<h1>Hello World!<h1>');
        res.end();
    } else if (url === '/google') {
        // do a 302 redirect
        res.writeHead(302, {
            location: 'https://google.com',
        });
        res.end();
    } else if (url === '/rprivate.com') {
        // do a 302 redirect
        res.writeHead(302, {
            location: 'https://private.com',
        });
        res.end();
    } else {
        // do a 404 redirect
        res.writeHead(404);
        res.write('<h1>Sorry nothing found!<h1>');
        res.end();
    }
});

const PORT = 3000;
server.listen(PORT);
const baseurl = `http://0.0.0.0:${PORT}`;
const google = `${baseurl}/google`;


/****
 * Test native http lib
 * @returns {Promise<void>}
 */
const testHttp = async () => {
    const trace = true;

    await httpSsrfGet({ trace, url: baseurl, ssrf: false });
    await httpSsrfGet({ trace, url: google, ssrf: false });
    await httpSsrfGet({ trace, url: `http://private.com:${PORT}`, ssrf: false });
    let hadFailedCnt = 0;
    try {
        await httpSsrfGet({ trace, url: baseurl, ssrf: true });
    } catch (err) {
        hadFailedCnt++;
    }
    assert(hadFailedCnt === 1);
    try {
        await httpSsrfGet({ trace, url: google, ssrf: true });
    } catch (err) {
        hadFailedCnt++;
    }
    assert(hadFailedCnt === 2);
    try {
        await httpSsrfGet({ trace, url: `http://private.com:${PORT}`, ssrf: true });
    } catch (err) {
        hadFailedCnt++;
    }
    assert(hadFailedCnt === 3);
    await httpSsrfGet({
        trace,
        url: `http://private.com:${PORT}`,
        ssrf: true,
        allowListDomains: ['xxxx.io', 'private.com'],
    });
};

/**
 * Test with request lib
 * @returns {Promise<void>}
 */
const testRequest = async () => {
    const trace = true;
    if ('EXTERNAL_YAML_URL_WHITE_LIST' in process.env) {
        // Requires ENV to have the following export/env var.
        // EXTERNAL_YAML_URL_WHITE_LIST=["private.com"]
        const allowListDomains = JSON.parse(process.env.EXTERNAL_YAML_URL_WHITE_LIST);
        await requestSsrfGet({
            trace,
            url: `http://private.com:${PORT}`,
            ssrf: true,
            allowListDomains: allowListDomains,
        });
    }
    await requestSsrfGet({ trace, url: baseurl, ssrf: false });
    await requestSsrfGet({ trace, url: google, ssrf: false });
    await requestSsrfGet({ trace, url: `http://private.com:${PORT}`, ssrf: false });
    var hadFailedCnt = 0;
    try {
        await requestSsrfGet({ trace, url: baseurl });
    } catch (err) {
        hadFailedCnt++;
    }
    assert(hadFailedCnt === 1);
    try {
        await requestSsrfGet({ trace, url: google });
    } catch (err) {
        hadFailedCnt++;
    }
    assert(hadFailedCnt === 2);
    try {
        await requestSsrfGet({ trace, url: `http://private.com:${PORT}` });
    } catch (err) {
        hadFailedCnt++;
    }
    assert(hadFailedCnt === 3);
    await requestSsrfGet({
        trace,
        url: `http://private.com:${PORT}`,
        ssrf: true,
        allowListDomains: ['xxxx.io', 'private.com'],
    });
    await requestSsrfGet({
        trace,
        url: `http://private.com:${PORT}`,
        ssrf: true,
        allowListDomains: process.env.EXTERNAL_YAML_URL_WHITE_LIST,
    });
    try {
        await requestSsrfGet({ trace, url: `http://rprivate.com:${PORT}`, ssrf: true });
    } catch (err) {
        hadFailedCnt++;
    }
    assert(hadFailedCnt === 4);
    await requestSsrfGet({
        trace,
        url: `http://rprivate.com:${PORT}`,
        ssrf: true,
        allowListDomains: ['xxxx.io', 'rprivate.com'],
    });
    try {
        await requestSsrfGet({
            trace,
            url: `http://rprivate.com:${PORT}`,
            ssrf: true,
            allowListDomains: ['xxxx.io', 'private.com'],
        });
    } catch (err) {
        hadFailedCnt++;
    }
    assert(hadFailedCnt === 5);

    try {
        const url = `http://private.com:${PORT}`;
        const options = requestSsrfOptions({ url });
        return await request(options);
    } catch (cause) {
        assert(isSsrfError(cause));
    }
};

const runtTests = async () => {
    await testHttp();
    await testRequest();
};

runtTests()
    .then(() => {
        console.log(`Done`);
        server.close();
    })
    .catch(error => {
        console.log(`Had err ${error}`, error);
        server.close();
        process.exit(1);
    });
