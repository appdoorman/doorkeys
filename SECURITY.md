# Security policy

This code holds customers' admin credentials for their apps, so reports about it are read first.

## Reporting a vulnerability

Write to **support@appdoorman.com** with "Security" in the subject. Please don't open a public issue
for a vulnerability. Say what you found, how to reproduce it and what it would let someone do.

You'll get an answer within three working days. Once a fix is released, the report is credited to
you in the release notes if you want that.

## What counts

- A request the Keyhole sends that a Doorkey's allowlist does not list, or to a host the Doorkey does
  not name.
- A way to load a spec that AppDoorman's signing key did not sign.
- A way for anything but the Keyhole to open a stored credential.
- A change reported as done without the read-back that should confirm it.
- A member list accepted as complete when it was not.

A problem in AppDoorman's service itself (appdoorman.com) goes to the same address.
