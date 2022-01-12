# Package `playground/ca`

This is a library and command line tool implementing a certificate authority for X.509 certificates. It was developed at Playground Global for internal use in a number of applications Playground Global requiring a CA. Using this API, and given an input X.509 certificate and RSA key, you can sign certificates suitable for use as client, server, and intermediate signing CAs.

That is, nothing you can't also do with `openssl`, just with all the fiddly bits set safely for you.

Special thanks to Playground Global, LLC for open-sourcing this software. See `LICENSE` for details.