# ssrf-safe
nodejs lib for SSRF safe request and filter
# Example for GET
Modify code:
```node
    try {
        return await request({
            method: 'GET',
            uri,
        });
    } catch (cause) {
    throw new NotFoundError({ cause });
}
```

By adding options
```node
    const { requestSsrfOptions } = require('@codefresh-io/ssrf-safe');
    const options = requestSsrfOptions({ url: uri });
    try {
        return await request({
            method: 'GET',
            options,
            uri,
        });
    } catch (cause) {
        throw new NotFoundError({ cause });
    }
```

## Example generic
add filter agent to the options
```node
const options = requestSsrfOptions({ url: uri });
        try {
            return await request({
                options: requestSsrfOptions({ options })
            });
        } catch (cause) {
            throw new NotFoundError({ cause });
        }
```
