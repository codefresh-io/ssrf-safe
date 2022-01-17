const assertLib = require('assert');
const assert = assertLib.strict;
const http = require('http');
const { httpSsrfGet, requestSsrfGet } = require('./ssrf');
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
};


const runtTests = async () => {
    await testHttp();
    await testRequest();
};
runtTests()
    .then(() => {console.log(`Done`);})
    .catch(error => {
        console.log(`Had err ${error}`, error);
        process.exit(1);
    });


setTimeout(
    (msg) => server.close(() => { console.log(msg);}),
    3 * 1000,
    `Server closed.`);
