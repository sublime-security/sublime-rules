# Sublime Rules
This repo contains open-source detection rules and queries, primarily for phishing defense.

Follow our [Quick Start Guide](https://docs.sublimesecurity.com/quick-start) to run these rules using the free Analysis API.

Learn more about [Message Query Language (MQL)](https://dev.docs.sublimesecurity.com/docs/message-query-language), Sublime's DSL purpose-built for email analysis.

Use our [Tutorials](https://dev.docs.sublimesecurity.com/docs/tutorials) to learn about the Sublime system and how to write your own rules.

Follow us on [Twitter](https://twitter.com/sublime_sec) for updates.

### Free Analysis API

The alpha Analysis API is a free API for analyzing messages using MQL. You need to Bring Your Own Messages, such as reported phish. 

The example below can be customized to detect homoglyph attacks:
```javascript
type.inbound
and iedit_distance(sender.email.domain.domain, 'YOURDOMAIN1.COM') < 2
```

### Sublime Platform
_Coming soon_
The [Sublime Platform](https://dev.sublimesecurity.com/products/platform/) has built-in connectors for Office 365, G Suite, and IMAP, and a pretty Dashboard. The Community Edition is and always will be completely free and self-hostable.

The example below can be used with the Platform to dynamically detect homoglyph attacks with frequent contacts:
```javascript
type.inbound
and iedit_distance(sender.email.domain.domain, $frequent_domains) < 2
```

Rules that return `true` in the Platform trigger actions such as SIEM alerts, auto-trash, or the insertion of a warning banner.

Sign up for [Platform early access here](https://dev.sublimesecurity.com/products/platform/).
