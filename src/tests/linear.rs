//! Linear: GraphQL on one endpoint, every operation allowlisted by root field, invites kept in a
//! list of their own, and Relay paging that ends only on `hasNextPage: false`.

use super::*;
use crate::fakes::linear as fake;

fn target(origin: &str, key: &str, page: u32) -> Target {
    let mut dk = fake::linear_doorkey(origin);
    for op in ["list_users", "list_invites"] {
        if let Some(Paginate::Cursor { size, .. }) = &mut dk.ops.get_mut(op).unwrap().paginate {
            *size = Some(page);
        }
    }
    Target::Doorkey(Keyhole::new(dk, key, sealer(), true).unwrap())
}

#[tokio::test]
async fn linear_invites_settles_suspends_unsuspends_and_withdraws() {
    let (origin, api) = fake::spawn_linear().await;
    for n in 0..3 {
        api.add_user(&format!("p{n}@acme.example"), false);
    }
    api.add_user("github@integrations.linear.app", true);
    // Pages of one: the walk follows endCursor until hasNextPage is false, though Linear keeps
    // endCursor set on the last page.
    let target = target(&origin, fake::LINEAR_KEY, 1);
    assert!(!target.supports_delete() && target.supports_withdraw() && target.supports_suspend());
    let users = target.list_users().await.unwrap();
    assert_eq!(users.iter().map(|u| u.user_name.as_str()).collect::<Vec<_>>(), ["p0@acme.example", "p1@acme.example", "p2@acme.example"], "app users are not people");
    // Every request is the signed document with only the variables filled in, paging included.
    let sent = api.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 4, "four pages of one, the last one saying hasNextPage false");
    assert_eq!(sent[0]["variables"], json!({ "first": 1 }));
    assert_eq!(sent[1]["variables"], json!({ "first": 1, "after": "user-0001" }));
    assert!(sent[0]["query"].as_str().unwrap().starts_with("query AppDoormanUsers("));

    // An invite is pending until accepted, then settled from the user list.
    let created = target.create_user("new@acme.example", "N", "H", "New@acme.example").await.unwrap();
    let Created::Pending(pending) = created else { panic!("an invite is pending until accepted") };
    assert_eq!(pending.evidence.verified_by, "list_users");
    // Linear lists the invitee at once as an inactive, never-seen placeholder; it is not a member.
    assert!(target.list_users().await.unwrap().iter().all(|u| u.user_name != "New@acme.example"), "an invitee's placeholder is left out");
    let last = api.sent.lock().unwrap().iter().rev().find(|b| b["query"].as_str().unwrap().contains("organizationInviteCreate")).cloned().unwrap();
    assert_eq!(last["variables"], json!({ "email": "New@acme.example" }));
    let id = api.accept("New@acme.example");
    assert!(target.list_users().await.unwrap().iter().any(|u| u.id == id && u.active));

    // Suspend and unsuspend, each read back from the full user list (suspended users included).
    let ev = target.set_active(&id, false).await.unwrap();
    assert_eq!((ev.op.as_str(), ev.verified_by.as_str(), ev.subject_id.as_str()), ("deactivate_user", "list_users", id.as_str()));
    assert_eq!(api.active(&id), Some(false));
    assert!(target.list_users().await.unwrap().iter().any(|u| u.id == id && !u.active), "a suspended user is still listed, inactive");
    let back = target.set_active(&id, true).await.unwrap();
    assert_eq!(api.active(&id), Some(true));
    assert_ne!(ev.request_fingerprint, back.request_fingerprint, "two operations on one path are told apart in the record");

    // A leaver who never accepted: their unaccepted invite is found by email, in any case, and
    // deleted, confirmed gone by its id.
    target.create_user("leaver@acme.example", "L", "V", "Leaver@Acme.example").await.unwrap();
    let ev = target.withdraw_invite("leaver@acme.example", "leaver@acme.example").await.unwrap();
    assert_eq!((ev.op.as_str(), ev.verified_by.as_str(), ev.subject_user_name.as_str()), ("withdraw_invite", "list_invites", "Leaver@Acme.example"));
    assert!(ev.subject_id.starts_with("invite-"), "the record names the invite it withdrew");
    assert!(api.invites.lock().unwrap().iter().all(|i| i["email"] != "Leaver@Acme.example"));
    // New's invite was accepted, so there is nothing to withdraw and nothing is sent.
    let err = keyhole_err(target.withdraw_invite("new@acme.example", "New@acme.example").await.unwrap_err());
    assert!(matches!(err, KeyholeError::LookupFailed { found: 0, .. }), "got {err:?}");
}

#[tokio::test]
async fn linear_withdrawal_is_confirmed_by_the_invites_id_not_its_email() {
    let (origin, api) = fake::spawn_linear().await;
    let target = target(&origin, fake::LINEAR_KEY, 50);
    // An old, accepted invite shares the email of the new one being withdrawn. Confirming by email
    // would find the old one and fail; confirming by the withdrawn invite's id does not.
    api.invites.lock().unwrap().push(json!({ "id": "invite-old", "email": "back@acme.example", "role": "user", "acceptedAt": "2026-01-01T00:00:00.000Z", "expiresAt": null }));
    target.create_user("back@acme.example", "B", "A", "back@acme.example").await.unwrap();
    let ev = target.withdraw_invite("back@acme.example", "back@acme.example").await.unwrap();
    assert_ne!(ev.subject_id, "invite-old");
    assert_eq!(api.invites.lock().unwrap().iter().map(|i| i["id"].as_str().unwrap().to_string()).collect::<Vec<_>>(), ["invite-old"]);
}

#[tokio::test]
async fn linear_fails_closed_on_graphql_errors_and_broken_paging() {
    let (origin, api) = fake::spawn_linear().await;
    let id = api.add_user("p0@acme.example", false);
    api.add_user("p1@acme.example", false);
    let target = target(&origin, fake::LINEAR_KEY, 1);

    // The key goes bare in Authorization; anything else is refused and nothing is read. A wrong key
    // is a 401, which stops the sync run.
    let err = keyhole_err(self::target(&origin, "Bearer lin_api_test", 1).list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::Http(400, _, Some(ref m)) if m.contains("Bearer")), "got {err:?}");
    let err = keyhole_err(self::target(&origin, "lin_api_revoked", 1).list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::Http(401, ..)), "got {err:?}");

    // HTTP 200 with an error beside partial data is a failure, never an empty list.
    *api.fail_with.lock().unwrap() = Some("Internal server error".into());
    let err = keyhole_err(target.list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::NotOk { ref error, .. } if error.contains("Internal server error")), "got {err:?}");
    *api.fail_with.lock().unwrap() = None;

    // A mutation answering success false, with HTTP 200, changes nothing and the read-back says so.
    *api.refuse.lock().unwrap() = true;
    let err = keyhole_err(target.set_active(&id, false).await.unwrap_err());
    assert!(matches!(err, KeyholeError::VerifyFailed(ref op) if op == "deactivate_user"), "got {err:?}");
    assert_eq!(api.active(&id), Some(true));
    *api.refuse.lock().unwrap() = false;

    // A Free workspace can invite only admins: the member invite fails with Linear's reason and
    // nothing is pending, so the admin sees why rather than a waiting invite.
    *api.free_plan.lock().unwrap() = true;
    let err = keyhole_err(target.create_user("new@acme.example", "N", "H", "new@acme.example").await.unwrap_err());
    assert!(matches!(err, KeyholeError::NotOk { ref error, .. } if error.contains("Not allowed on free plan")), "got {err:?}");
    assert!(api.invites.lock().unwrap().is_empty());
    *api.free_plan.lock().unwrap() = false;

    // A GraphQL error on a mutation (an unknown id) fails the change.
    let err = keyhole_err(target.set_active("user-9999", false).await.unwrap_err());
    assert!(matches!(err, KeyholeError::NotOk { ref error, .. } if error.contains("Entity not found")), "got {err:?}");

    // An API that ignores the cursor, or leaves out hasNextPage, is an incomplete read.
    *api.ignore_after.lock().unwrap() = true;
    assert!(matches!(keyhole_err(target.list_users().await.unwrap_err()), KeyholeError::Incomplete { .. }));
    *api.ignore_after.lock().unwrap() = false;
    *api.drop_has_next.lock().unwrap() = true;
    let err = keyhole_err(target.list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::Incomplete { ref why, .. } if why.contains("hasNextPage")), "got {err:?}");
}

#[test]
fn the_linear_doorkey_is_capped_to_its_operations() {
    let load = |edit: &dyn Fn(&mut Value)| {
        let mut dk: Value = serde_json::from_str(include_str!("../../doorkeys/linear.doorkey.json")).unwrap();
        dk["base_url"] = json!("http://127.0.0.1:1");
        dk["hosts"] = json!(["127.0.0.1"]);
        edit(&mut dk);
        serde_json::from_value::<Doorkey>(dk).map_err(|e| e.to_string()).and_then(|d| Keyhole::new(d, "k", sealer(), true).map(|_| ()).map_err(|e| format!("{e:#}")))
    };
    load(&|_| {}).unwrap();
    // A root field the allowlist does not name is refused, aliased or not.
    let err = load(&|dk| dk["ops"]["deactivate_user"]["request"]["graphql"]["query"] = json!("mutation M($id: String!) { userSuspend: userPromoteAdmin(id: $id) { success } }")).unwrap_err();
    assert!(err.contains("not covered by the allowlist"), "{err}");
    // A paging variable the document does not declare would page the same answer forever.
    let err = load(&|dk| dk["ops"]["list_users"]["request"]["graphql"]["query"] = json!("query Q($first: Int!) { users(first: $first, includeDisabled: true) { nodes { id email active app } pageInfo { hasNextPage endCursor } } }")).unwrap_err();
    assert!(err.contains("`after`"), "{err}");
    // A read-back `by` a value no lookup provides is refused.
    let err = load(&|dk| dk["ops"]["withdraw_invite"]["verify"]["absent"]["by"] = json!("other_id")).unwrap_err();
    assert!(err.contains("none of its lookups"), "{err}");
    // Only reads that find and confirm an invite may lack the `active` flag the user list has.
    let err = load(&|dk| dk["ops"]["deactivate_user"]["verify"]["present"]["op"] = json!("list_invites")).unwrap_err();
    assert!(err.contains("disagrees with `list_users`"), "{err}");
}
