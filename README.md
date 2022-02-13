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
            ...options
        });
    } catch (cause) {
        throw new NotFoundError({ cause });
    }
```

## Example generic
add filter agent to the options
```node
const options = { uri };
        try {
            return await request(
              requestSsrfOptions({ options })
            );
        } catch (cause) {
            throw new NotFoundError({ cause });
        }
```
 
## Using logs
```node
const options = { uri };
        try {
            return await request(
              requestSsrfOptions({ options })
            );
        } catch (cause) {
            logSsrfError(err, logger.warning);
            throw new NotFoundError({ cause });
        }
```