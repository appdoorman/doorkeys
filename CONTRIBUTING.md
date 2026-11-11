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

Doorkey specs are licensed under Apache-2.0, and a spec you contribute is licensed the same way.

Code is published under the AGPL-3.0. AppDoorman also runs this code inside its own hosted
service, which is not open source, so a code contribution needs one more permission. By opening a
pull request that changes code, you agree that:

- you wrote the contribution, or otherwise have the right to submit it;
- it is licensed to everyone under the AGPL-3.0, like the rest of the code; and
- you also grant AppDoorman's owner (named in the [imprint](https://appdoorman.com/imprint)) a
  perpetual, worldwide, non-exclusive, royalty-free, irrevocable licence to use, modify and
  distribute it as part of AppDoorman's products, including under other licence terms.

You keep the copyright in what you contribute. If you can't agree to this, open an issue
describing the change instead.
