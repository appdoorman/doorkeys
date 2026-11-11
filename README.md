# AppDoorman Keyhole and Doorkeys

[AppDoorman](https://appdoorman.com) provisions accounts in SaaS apps from Google Workspace groups.
For an app whose plan has no SCIM, it uses the app's own admin API, and to do that it needs an
admin credential for the app. This repository is the code that holds and uses that credential, so
anyone can check what it does with it.

- A Doorkey is a signed spec for one app: every request AppDoorman may ever send to that app,
  reads included, and the read-back that must confirm each change. The specs are in
  [`doorkeys/`](doorkeys), with the format described in [`doorkeys/README.md`](doorkeys/README.md).
- The Keyhole is the only process that can open a stored credential. It loads only specs signed
  with AppDoorman's offline key, sends only requests the spec lists, only to the hosts the spec
  names, and signs evidence of every change. The engine is [`src/lib.rs`](src/lib.rs) and the
  service is [`src/service.rs`](src/service.rs).

## What is here, and what is not

| Here | Not here |
|---|---|
| The Doorkey engine and the Keyhole service | AppDoorman's sync engine, planner and safety rules |
| The signed specs for the apps AppDoorman offers | The web app, the Slack app, billing |
| The key helpers and the SSRF-safe HTTP client they use | The private signing key, which never leaves the maintainer |
| The SCIM client and the mock SCIM app the tests run against | |

This package does not sync anything by itself. AppDoorman's own service builds on it.

## Check it yourself

```bash
cargo test
```

```bash
cargo run --bin doorkey-verify -- doorkeys/*.doorkey.json
```

The first runs the engine against stand-ins for each app's API, built from the app's documentation.
The second checks every spec's signature against the public key in
[`doorkeys/doorkey-signing.pub`](doorkeys/doorkey-signing.pub), the same key the Keyhole has built
in.

## Licences

The code is licensed under the [GNU Affero General Public License v3.0](LICENSE). The Doorkey specs
in `doorkeys/` are licensed under the [Apache License 2.0](doorkeys/LICENSE).

## Security and contributions

Report a vulnerability as [`SECURITY.md`](SECURITY.md) describes. New Doorkeys and changes are
welcome as pull requests; [`CONTRIBUTING.md`](CONTRIBUTING.md) says how they are reviewed, tested
and signed.
