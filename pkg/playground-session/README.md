# Package `playground/session`

This package implements a Google OAuth2 client for authentication to a third-party web site. That is, it allows you to authenticate users to your site via their Google accounts, using OAuth2.

This library was created some years ago, predating the various open-source implementations that support not just Google but other OAuth2 providers. Accordingly, there's not much reason to start using this library, today: use one of the others instead. It was released as it is a dependency for other applications being released by Playground Global.

That said, as a straightforward implementation of an OAuth2 client, it may be useful as a reference or demo, since it clearly illustrates the flow without being obscured by the abstractions necessary to support multiple providers.

Special thanks to Playground Global, LLC for open-sourcing this software. See `LICENSE` for details.
