# Doorkeys

A Doorkey is a versioned spec that lets AppDoorman provision and deprovision users in an app whose
plan gives the customer no SCIM. The engine that runs it is in [`src`](../src). The Keyhole is the
only component that holds the app's credential and makes the calls, and it refuses any request the
Doorkey does not list.

| Spec | What it manages | Credential |
|---|---|---|
| `anthropic` | Members of a Claude Console or Claude Enterprise organization | Admin API key |
| `asana` | Members of an Asana organization below Enterprise | Admin's personal access token |
| `atlassian` | Users and groups of an Atlassian organization without Guard | Organization API key without scopes |
| `cloudflare` | Members of a Cloudflare account, on every plan | Account API token |
| `github` | Members and teams of a GitHub organization on Free or Team | Organization owner's token |
| `github-copilot` | Copilot Business seats | Organization owner's token |
| `linear` | Users of a Linear workspace on Basic or Business (GraphQL) | Admin's personal API key |
| `microsoft365` | Accounts and licences in a tenant federated with Google Workspace | App registration with a client secret |
| `openai` | Members of an OpenAI Platform organization | Admin API key |
| `mock` | The built-in mock SCIM app, in dev mode only | A test token |

Each spec's `_comment` says where its API is documented, what the credential needs and how the
app behaves. `mock.doorkey.json` is the worked reference; copy it to
start a new one.

## Scope

A Doorkey is only used when the customer's plan has no SCIM. If their plan includes SCIM (AWS, Adobe
Enterprise, …), AppDoorman uses the normal SCIM setup and no Doorkey is involved.

## Anatomy

Unknown keys are refused when a Doorkey loads, at every level: a misspelled `paginate` or
`ok_field` would otherwise load fine and quietly switch that protection off. Notes for reviewers go
in `_comment` (a string or an object), allowed at the top level and on each op.

- `base_url`: the app's admin-API origin and prefix. AppDoorman replaces it with the customer's
  workspace URL, which goes through the same checks as a SCIM URL: public HTTPS only outside dev
  mode, no credentials, query or fragment.
- `hosts` (required): the hosts the credential may be sent to: `api.example.com` exactly, or
  `*.example.com` for any subdomain of it (not `*.com`). The workspace URL must be on one of them,
  checked when the app is set up, when its URL is edited and every time a Keyhole is built, so an
  admin credential can never be pointed at another server. `*` (any host) only works in dev mode, for
  the built-in mock.
- `auth`: how the Keyhole presents its secret (`bearer`, a named `header`, or
  `oauth_client_credentials`). The secret itself is never in the Doorkey; the Keyhole injects it at
  runtime.
- `ok_field`: for an app that answers HTTP 200 with a success flag (an `ok` or `success` field) and the failure
  in an `error` field. When set, a 2xx response counts only when that dotted path is `true`;
  otherwise the op fails closed.
- `headers` (optional): constant headers every request carries, such as Anthropic's
  `anthropic-version`. Part of the signed spec, never templated, printable only, and never one that
  carries a credential or frames the request (`Authorization`, `Cookie`, `Host`, `Content-Type`, …,
  or the header the `auth` scheme names). `Accept` may be set; it replaces the default JSON one.
- `allow`: every request the Keyhole may ever send, reads included: method, path pattern and,
  optionally, `params`, the query parameter names it may carry. A request is checked with
  its path exactly as it will be sent (after URL normalisation) and refused before it leaves the
  process when no rule covers it; a Doorkey with an op no rule covers is refused when it loads.
  Reads are checked because RPC-style admin APIs change state on a GET or with an extra
  argument. This is the hard cap on blast radius: list, add and remove members, and nothing else.
- `ops`: the lifecycle actions. The engine expects these names:
  - `list_users` (required) and `find_user`: reads (`GET`, or a GraphQL `query`).
  - `create_user`: context: `{user_name, given, family, email}`.
  - `deactivate_user`, `reactivate_user`: context: `{id, active}`.
  - `delete_user`: context: `{id}`.
  - `withdraw_invite` (optional): context: `{user_name, email}`. Withdraws the pending invite of
    someone who left every assigned group before accepting, so it stops working at once (and stops
    holding a seat where the app counts one). It finds the invite with a `lookup` and must confirm
    with an `absent` read-back. The sync run calls it only when it applies changes; when the app
    shows no pending invite for them, the invite stays on record so a late acceptance is still
    settled and removed.
- `lookup` (optional, per op): values the request needs that differ from account to account, read
  from the app first: `{"role_id": {"op": "list_roles", "list": "result", "where": {"name":
  "Administrator"}, "take": "id"}}` puts the id of the one role named Administrator in `{role_id}`.
  A `where` value may name the subject, `{"email": "{user_name}", "status": "pending"}`, to find
  someone's invite; such a value matches in any case, as email addresses do. The op must be a read (a GET or a GraphQL
  query) without lookups of its own; no match, or more than one, sends nothing. A lookup cannot replace
  the values the engine provides (`id`, `email`, …). With `"single": true` and no `where`, it
  takes the one item a read the request already filters returns (`GET /directories?accountId={id}`
  for Atlassian, whose changes need the user's own directory); none, or several, sends nothing.
- `request`: `method`, an absolute `path` with `{param}` placeholders (no `?`, `#` or `.`/`..`
  segments), optional `query` parameters, and a JSON `body`. A placeholder with no value is an error; a path
  value that is empty, `.` or `..` is refused.
- `graphql` (in `request`, optional): for an app whose admin API is GraphQL; see GraphQL ops below.
- `extract`: where the user fields are, as dotted paths (`profile.email`). `list` names the array
  in a list response (`""` when the app answers with the bare array, as GitHub does); omit it for
  a single-user response. `user_name` must be the field that holds
  the email address, not a handle or display name: the planner adopts the account a person
  already has by matching their email. Every field must be there: a user without an id, user name
  or active flag is an error, never a default. Set `active_inverted: true` when the field named by
  `active` really records the opposite (a `deleted` or `disabled` flag). For an app that
  records a status string instead of a flag, set `active_when` to the value that means active
  (`"active_when": "active"` for Atlassian's `status`): any other value of the same type is
  inactive, and a missing or differently typed field is an error. Leave `active` out
  of every op for an app that only lists members (Cloudflare): every listed user is active, the
  Doorkey has no `deactivate_user` or `reactivate_user`, it must have `delete_user`, and the sync
  run turns any rule that would suspend into a removal, since nothing else takes access away. `skip` lists the
  items that are not people, each as a dotted path and its value, e.g.
  `[{"is_bot": true}, {"type": "service_account"}]`; an item matching every field of an entry is left out.
  Name non-people precisely: a skipped person is a leaver nobody removes. `skip_when_set` lists
  dotted paths that leave an item out when they hold any value but null: Copilot's
  `["pending_cancellation_date", "assigning_team"]` drops seats already cancelled and seats a
  GitHub team manages.
- `paginate`: how a list op walks pages:
  - `{"style": "offset", "param", "size_param", "size", "first", "total"?}`: `first` is 1 for SCIM's
    `startIndex`, 0 for a plain offset.
  - `{"style": "page", "param", "size_param", "size", "first", "total"?}`: page numbers.
  - `{"style": "cursor", "param", "next", "size_param"?, "size"?, "more"?}`: `next` is the dotted
    path to the next cursor. `more` is the dotted path to a has-more flag (a GraphQL connection's
    `pageInfo.hasNextPage`): when set, only `false` ends the walk, and a missing flag, or `true`
    without a cursor, is an error. Set it wherever the app keeps the cursor on the last page.

  Walks end on an empty page, when `total` is reached, or when the cursor runs out. They fail,
  rather than return a short list, when a page holds only users already read (the app ignores the
  paging parameters), when the cursor comes back unchanged, when the list ends short of the
  reported `total`, or after 1000 pages. An empty page with a new cursor is not the end.
- `verify`: the read-back, and the reason a Doorkey can be trusted. Every mutating op must have
  one, and it must go through a read op (a `GET` or a GraphQL `query`) with an `extract` block. The user is found by `id` (or
  `user_name` when there is no id yet), across every page when the read op is a list:
  - `present`: the user is there with the `expect`ed fields. `expect` may use `{param}`
    placeholders, e.g. `"user_name": "{user_name}"`.
  - `absent`: the user is gone. With `"by": "<lookup key>"` the item is found by a value one of
    the op's lookups found instead (`withdraw_invite` confirming by the invite's own id, where an
    accepted invite may share the email).

  Prefer a single-user read for `verify` where the app has one: a list read-back walks every page.
- `allow_pending` (only on `create_user`, only with a `present` verify): for an app that takes the
  request but only lists the user later, as an invite does until it is accepted. When the read-back
  cannot find the user at all, the create comes back as `Created::Pending` with sealed evidence
  instead of failing. AppDoorman records the invite and never sends it
  again. Each later run settles it from the member list it reads anyway: once the person is
  listed they become a managed account, before planning, so someone who joins after leaving their
  groups is still deprovisioned. An invite still waiting after 14 days is reported as a failed
  change on every run until someone resends it in the app or removes the person from the group.
  A user who shows up but not as expected (for example deactivated) is still a failed change,
  never a pending one.
- `shape` (optional, per op): a fingerprint of the response's structure (of one user item, for a
  list op). If the app changes its response format, the op fails with `ShapeChanged` so the Doorkey
  is re-recorded for every tenant before any change is attempted.

## GraphQL ops

A GraphQL admin API (Linear's, for one) takes every call as a `POST` to one path, so method and
path alone cannot tell a member list from a billing change. A GraphQL op puts the operation in
`request.graphql` instead of a `body`:

```json
"request": { "method": "POST", "path": "/graphql", "graphql": {
  "query": "mutation Suspend($id: ID!) { suspendUser(id: $id) { user { id } errors { code message } } }",
  "variables": { "id": "{id}" },
  "errors_at": ["data.suspendUser.errors"]
} }
```

- The document is fixed. It is part of the signed spec and sent exactly as written; only
  `variables` are templated, as a JSON body is, and each must be declared by the document. The
  document must be one operation with an explicit `query` or `mutation` keyword: no `{ … }`
  shorthand, `subscription`, fragments, `...` spreads or directives. The op is a `POST` with no
  `body` or `query` beside it.
- Reads and changes come from the document. A `query` op is a read, so it can be `list_users`,
  a read-back, a guard or a lookup source. A `mutation` op is a change and needs a `verify`.
- The allowlist names root fields. A rule with `"graphql": ["users", "suspendUser"]`
  covers a GraphQL op on its method and path only when every field the document selects at its top
  level (aliases resolved) is listed. A rule without `graphql` never covers a GraphQL op, and a
  GraphQL rule never covers a REST request. Set `"params": []` so no URL parameter rides along.
- Paging goes in variables. For a GraphQL op, the `param` and `size_param` of an `offset`,
  `page` or `cursor` walk name variables the document declares; numbers are sent as `Int`, cursors
  as `String`.
- HTTP 200 is not success. A GraphQL API answers 200 for a failed operation, so a 2xx counts
  only when it has `data`, a missing or empty `errors` array, and nothing at each `errors_at` path
  (where an API reports the per-user failures of a mutation). Partial data with errors
  fails too. The failure carries the error's `extensions.code` and message.
- Invites may have a list of their own. The reads `withdraw_invite` uses only to find and confirm an
  invite (Linear's `organizationInvites`) may leave out the `active` field `list_users` has, since
  an invite has no such flag. Any read that also serves another op must agree with `list_users`.

## Group push

A Doorkey can push Google groups as groups in the app, the way SCIM apps do, with four ops and an
optional fifth:

- `list_groups`: a GET op with a `groups` block (`{"list", "id", "name"}`) instead of `extract`:
  where the app's groups are, by id and name.
- `list_group_members`: a GET op with a user `extract` and `list`, given `{group_id}`: the
  group's members, read the same way as `list_users`.
- `add_group_member`, `remove_group_member`: context `{group_id, id}`, each read back through
  `list_group_members` (`present`, `absent`).
- `create_group` (optional): context `{name}`, read back as `present` through `list_groups` with
  `{"name": "{name}"}`; two groups by that name is a failed read-back, never a pick. Without it,
  only a group that already exists in the app by that name is kept in step.

They come as a set or not at all. The sync run finds a group it manages by its id and any other
by its exact name (two by that name push nothing), adds and removes only members AppDoorman
manages, one at a time, and keeps each change as evidence. A Doorkey has no rename, so a group
renamed in Google keeps its old name in the app.

## Settling

An app that shows a change a moment after it accepts it (Atlassian's single-user read, one to two
seconds late) names a `settle`: `{"tries": 6, "wait_ms": 1500}` reads the change back up to six
times, waiting between reads, before it counts as failed. Only a read that disagrees, or finds
nobody yet, is tried again; an error never is. At most 10 tries and 5000 ms between them.

## Hints

Some apps refuse a call with a message that doesn't say what to fix: OpenAI answers "We couldn't
send this invite right now" whether the organization lacks a payment method or its owner is on
Gmail. A Doorkey's signed `hints` map such an app's error code (`error.code`, `code` or
`error_code`) to the instruction the admin sees in its place:
`{"block_invite_organization_user": "…make someone on your company's domain the organization's owner."}`.
A code without a hint keeps the app's own message.

## Rate limits

A request the app answers with `429` is sent again after the `Retry-After` it asks for (at most
30 seconds), three tries in all; a 429 means the app did not act on it. An app still refusing
after that stops the sync run, which tries again on its next schedule.

## Reads fail closed

A member list that cannot be read in full (a 404, an HTML page where JSON was expected, a missing
list field, a user without an id, an app that stops paging or lists
fewer users than it reports) is an error, never an empty or partial list. The planner would
otherwise read a missing managed user as an account removed outside AppDoorman and stop managing
it, so a leaver would keep their access.

## The Keyhole service

The Keyhole is the only code that opens a credential or calls a Doorkey app, and it runs either
inside the server (dev, tests, a server without the service) or as its own process, under its own
user with its own key, which is how AppDoorman runs it in production. The web app reaches it over a Unix socket only the web app's group can open, with one call per
connection: `info`, `seal`, `list_users`, `create_user`, `set_active`, `delete_user`.

- Credentials are sealed by the Keyhole (`kh1.<key id>.<ciphertext>`) for one app of one
  workspace, so what the web app stores it cannot open, and a credential copied to another app or
  server does not open there. A credential saved earlier (with the workspace key, or by the
  in-process Keyhole) is sealed again by the active Keyhole on its next use.
- The caller names a Doorkey by id; the Keyhole loads only the signed, bundled spec. A
  compromised web app can still ask for the allowlisted member changes, but cannot read an admin
  credential, send it elsewhere, or widen what it may do.
- Errors cross the socket as they are, so the sync run still tells a refused credential (which stops
  the run) from one failed change, and an unreachable Keyhole is an error, never an empty list.

## Evidence

Every confirmed change returns a record: the workspace and app, the op, the request, the user's id
and user name, the read op that confirmed it, the hash of the app's previous record, and an Ed25519
signature over all of it by the Keyhole, with a key of its own per workspace. AppDoorman stores
each record, so every app has a chain: a record edited, removed or moved to another app breaks it.
The chain is checked against the Keyhole's public keys, which anyone can use to check an exported
record too.

## Canary

The canary (`src/canary.rs`) runs a signed Doorkey against a sandbox workspace of the app: it reads
the whole member list and, given a test account, deactivates and reactivates it, each confirmed by
the read-back. AppDoorman runs it on a schedule to catch an app that changed before a customer's
change needs it. It reads a file, `{"doorkey", "base_url", "credential", "test_user_id"?}`, which
holds a real credential and must stay out of any repository.

## Authoring a new one

1. Read the app's official admin API documentation and write each lifecycle action as an op. Use
   only documented endpoints that work on the plan a customer would have.
2. Check every path against `allow`, and give every change a `verify`.
3. Add a stand-in for the app's API under `src/fakes` and tests that run the spec against it.
4. In your own test workspace of the app, on that plan, run create, deactivate and delete, each
   with its read-back, until all pass. Note anything the documentation does not say in the
   spec's `_comment`.
5. Open a pull request. The spec is reviewed, run again and signed before it is merged
   (see [`CONTRIBUTING.md`](../CONTRIBUTING.md)). Anyone can check the result:

   ```bash
   cargo run --bin doorkey-verify -- doorkeys/<app>.doorkey.json
   ```

## Signatures

Every bundled spec ships with a detached Ed25519 signature (`<spec>.sig`) over its exact bytes.
The Keyhole only loads a spec whose signature checks out against the public key built into the
binary (`doorkey-signing.pub`), so a spec cannot be changed in the repository, the build or the
binary without the private key. That key is kept offline by AppDoorman's maintainer and is not in
this repository. A test fails when a spec changes without being signed again, and `.gitattributes`
keeps line endings exactly as signed.

## What gets no Doorkey

An app with no documented member-management API on the customer's plan gets no Doorkey. Only
official admin APIs are used, never an app's internal endpoints or a copied browser session.
