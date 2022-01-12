# Package `playground/config`

This library loads config data out of JSON files via Go's standard `json` package, populating configuration objects and command line. Essentially it's a simple ORM for JSON config.

Also supports overriding top-level JSON config entries from command-line flags. That is, you can't
override nested config values, which is by design since the UX for that would be pretty hairy and
for limited value, since typically the top-level ones are the "big" ones you want to override.

Overrides are accomplished via a struct field tag of `config:"flag_name;description"` on the config
struct.

Special thanks to Playground Global, LLC for open-sourcing this software. See `LICENSE` for details.
