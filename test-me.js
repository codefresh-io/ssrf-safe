const assertLib = require('assert');
const assert = assertLib.strict;

const http = require('http');
const request = require('request-promise');
const { requestSsrfOptions, isSsrfError, logSsrfError, getAgent, getAllowList } = require('./index');

/*******
 * Test Helper methods
 */

/**
 * Native node http lib use of ssrf agent
 */
async function httpSsrfGet({ url, ssrf = false, allowListDomains = [] }) {
    const callLog = console.log
    callLog(`Calling ${url} ssrf:${ssrf} allowListDomains:${allowListDomains}`);
    const options = ssrf ? {
        agent: getAgent({ url, allowListDomains, callLog }),
        callLog
    } : {};
    const waitfor = new Promise((resolve, reject) => {
        let data = [];
        callLog(`http.get ${url},  ${JSON.stringify(options)}`);
        http.get(url, options, res => {
            const headerDate = res.headers && res.headers.date ? res.headers.date : 'no response date';
            callLog('Status Code:', res.statusCode);
            callLog('Date in Response header:', headerDate);

            res.on('data', chunk => {
                data.push(chunk);
            });

            res.on('end', () => {
                callLog('Response ended: ');
                resolve({ data: data.join(''), statusCode: res.statusCode });
            });
        })
            .on('error', err => {
                logSsrfError(err, callLog);
                reject(err);
            });
    });
    const result = await waitfor;
    callLog(`Called ${url} return ${JSON.stringify(result)}`);
    return result;
}

/**
 * convenience method for doing request get.
 * @param url
 * @param ssrf
 * @param allowListDomains
 * @returns {Promise<*>}
 */
async function requestSsrfGet({ url, ssrf = true, allowListDomains = [] }) {
    const callLog = console.log
    callLog(`requestGet Calling ${url} ssrf: ${ssrf} allowListDomains:${allowListDomains}`);
    const options = ssrf ? requestSsrfOptions({ url, callLog, allowListDomains }) : { uri: url };
    try {
        const result = await request(options);
        callLog(`requestGet Called ${url} return ${JSON.stringify(result)}`);
        return result;
    } catch (err) {
        logSsrfError(err, callLog);
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
    } else if (url === '/xss') {
        // xss payload
        // to mitigate that and prevent inline script form running, add the following header
        // “content-security-policy: default-src 'self'“
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.write("<script>alert('Malicious XSS');alert(document.cookie)</script>");
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
    await httpSsrfGet({ url: baseurl, ssrf: false });
    await httpSsrfGet({ url: google, ssrf: false });
    await httpSsrfGet({ url: `http://private.com:${PORT}`, ssrf: false });
    let hadFailedCnt = 0;
    try {
        await httpSsrfGet({ url: baseurl, ssrf: true });
    } catch (err) {
        hadFailedCnt++;
    }
    assert(hadFailedCnt === 1);
    try {
        await httpSsrfGet({ url: google, ssrf: true });
    } catch (err) {
        hadFailedCnt++;
    }
    assert(hadFailedCnt === 2);
    try {
        await httpSsrfGet({ url: `http://private.com:${PORT}`, ssrf: true });
    } catch (err) {
        hadFailedCnt++;
    }
    assert(hadFailedCnt === 3);
    await httpSsrfGet({
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
    const callLog = console.log;
    const allowList = getAllowList();
    if (allowList) {
        // Requires ENV to have the following export/env var.
        // EXTERNAL_YAML_URL_WHITE_LIST=["private.com"]
        const allowListDomains = JSON.parse(allowList);
        await requestSsrfGet({
            url: `http://private.com:${PORT}`,
            ssrf: true,
            allowListDomains: allowListDomains,
        });
    }
    await requestSsrfGet({ url: baseurl, ssrf: false });
    await requestSsrfGet({ url: google, ssrf: false });
    await requestSsrfGet({ url: `http://private.com:${PORT}`, ssrf: false });
    let hadFailedCnt = 0;
    try {
        await requestSsrfGet({ url: baseurl });
    } catch (err) {
        hadFailedCnt++;
        logSsrfError(err, callLog)
    }
    assert(hadFailedCnt === 1);
    try {
        await requestSsrfGet({ url: google });
    } catch (err) {
        hadFailedCnt++;
        logSsrfError(err, callLog)
    }
    assert(hadFailedCnt === 2);
    try {
        await requestSsrfGet({ url: `http://private.com:${PORT}` });
    } catch (err) {
        hadFailedCnt++;
        logSsrfError(err, callLog)
    }
    assert(hadFailedCnt === 3);
    await requestSsrfGet({
        url: `http://private.com:${PORT}`,
        ssrf: true,
        allowListDomains: ['xxxx.io', 'private.com'],
    });
    try {
        await requestSsrfGet({ url: `http://rprivate.com:${PORT}`, ssrf: true });
    } catch (err) {
        hadFailedCnt++;
        logSsrfError(err, callLog)
    }
    assert(hadFailedCnt === 4);
    await requestSsrfGet({
        url: `http://rprivate.com:${PORT}`,
        ssrf: true,
        allowListDomains: ['xxxx.io', 'rprivate.com'],
    });
    try {
        await requestSsrfGet({
            url: `http://rprivate.com:${PORT}`,
            ssrf: true,
            allowListDomains: ['xxxx.io', 'private.com'],
        });
    } catch (err) {
        hadFailedCnt++;
        logSsrfError(err, callLog)
    }
    assert(hadFailedCnt === 5);

    try {
        const options = requestSsrfOptions({ url: `http://private.com:${PORT}`, callLog });
        return await request(options);
    } catch (err) {
        assert(isSsrfError(err));
        logSsrfError(err, callLog)
    }
    assert(!isSsrfError(new Error('Not Ssrf error')));


    try { // 404
        const options = requestSsrfOptions({
            url: `http://private.com:${PORT}/notfound`, callLog, allowListDomains: ['private.com']
        });
        return await request(options);
    } catch (err) {
        hadFailedCnt++;
        logSsrfError(err, callLog)
    }
    assert(hadFailedCnt === 6);
};

const runtTests = async () => {
    await testHttp();
    await testRequest();
};

runtTests()
    .then(() => {
        console.log(`Done`);
        if (process.argv.includes('stay'))  {
            console.log('Stay up');
        } else {
            server.close();
        }
    })
    .catch(error => {
        console.log(`Had err ${error}`, error);
        server.close();
        process.exit(1);
    });
