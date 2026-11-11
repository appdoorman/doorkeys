# Contributing

Thanks for looking. This repository is small on purpose: it is the part of AppDoorman that touches
customers' credentials.

## A new Doorkey, or a change to one

1. Write the spec from the app's official admin API, following
   [`doorkeys/README.md`](doorkeys/README.md). Only documented APIs: no internal endpoints and no
   browser sessions.
2. Add a stand-in for the app's API and tests that run the spec against it (see `src/fakes.rs` and
   `src/tests.rs`), including what happens when the app refuses, pages, or answers late.
3. Open a pull request. Say which plan of the app you tested on and what you could not test.

A Doorkey ships only after AppDoorman's maintainer has reviewed it, run it against a real test
account of the app, and signed it with the offline key. A contributed spec therefore arrives
unsigned, and the signature is added before it is merged. Not every contribution can be taken: an
app has to be testable on the plan its customers would have.

## Changes to the engine or the Keyhole

Open an issue first for anything beyond a small fix. Every change needs tests, and nothing may
loosen what the Keyhole refuses: requests outside a Doorkey's allowlist, hosts a Doorkey does not
name, unsigned specs, changes without a read-back, and incomplete member lists.

## Licence

By contributing you agree that your contribution is licensed as the rest of the repository: code
under the AGPL-3.0, Doorkey specs under Apache-2.0.
