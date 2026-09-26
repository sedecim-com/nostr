//! FR025-04: an MDK peer (Rust Marmot Development Kit, in-memory storage) for the marmot-ts <-> MDK interop
//! test. It talks to a real Nostr relay with nostr-sdk and is driven over stdin/stdout, one JSON object per
//! line, by tests/interop/marmot-mdk.interop.test.ts:
//!
//!   mdk-harness --relay ws://127.0.0.1:PORT [--secret HEX]
//!   -> {"ready":true,"pubkey":"<hex>","mdk":"<version>"}
//!   <- {"op":"publish_key_package"}                         -> {"ok":true,"event": <kind 30443 event>}
//!   <- {"op":"accept_welcomes"}                             -> {"ok":true,"groups":[...],"errors":[...]}
//!   <- {"op":"sync","group":"<mls group id hex>"}           -> {"ok":true,"messages":[...],"results":[...]}
//!   <- {"op":"send","group":"<hex>","content":"..."}         -> {"ok":true,"event_id":"<hex>"}
//!   <- {"op":"create_group","name":"...","members":["<pubkey hex>"],"kinds":[30443]} -> {"ok":true,"group":{...}}
//!   <- {"op":"quit"}
//!
//! Every response carries `ok`; failures carry `error` (the MDK/nostr error text) so the test can report
//! a precise incompatibility instead of a timeout.

use std::collections::HashSet;
use std::time::Duration;

use mdk_core::messages::MessageProcessingResult;
use mdk_core::prelude::*;
use mdk_memory_storage::MdkMemoryStorage;
use nostr_sdk::prelude::*;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const MDK_VERSION: &str = "mdk-core 0.8.0 (mdk-memory-storage 0.8.0)";
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

struct Peer {
    keys: Keys,
    client: Client,
    relay: RelayUrl,
    mdk: MDK<MdkMemoryStorage>,
    /// kind 445 events already handed to MDK (all groups).
    seen: HashSet<EventId>,
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn group_json(mdk: &MDK<MdkMemoryStorage>, g: &mdk_storage_traits::groups::types::Group) -> Value {
    let members: Vec<String> = mdk
        .get_members(&g.mls_group_id)
        .map(|m| m.iter().map(|p| p.to_hex()).collect())
        .unwrap_or_default();
    json!({
        "mls_group_id": hex::encode(g.mls_group_id.as_slice()),
        "nostr_group_id": hex::encode(g.nostr_group_id),
        "name": g.name,
        "epoch": g.epoch,
        "admins": g.admin_pubkeys.iter().map(|p| p.to_hex()).collect::<Vec<_>>(),
        "members": members,
    })
}

fn group_id(cmd: &Value) -> Result<GroupId, String> {
    let hex_id = cmd["group"].as_str().ok_or("missing group")?;
    Ok(GroupId::from_slice(
        &hex::decode(hex_id).map_err(|e| e.to_string())?,
    ))
}

impl Peer {
    async fn publish(&self, event: &Event) -> Result<(), String> {
        let out = self
            .client
            .send_event(event)
            .await
            .map_err(|e| e.to_string())?;
        if out.success.is_empty() {
            return Err(format!(
                "relay rejected kind {}: {:?}",
                event.kind, out.failed
            ));
        }
        Ok(())
    }

    async fn publish_key_package(&mut self) -> Result<Value, String> {
        let data = self
            .mdk
            .create_key_package_for_event(&self.keys.public_key(), [self.relay.clone()])
            .map_err(|e| e.to_string())?;
        let event = EventBuilder::new(Kind::Custom(30443), data.content)
            .tags(data.tags_30443)
            .sign_with_keys(&self.keys)
            .map_err(|e| e.to_string())?;
        self.publish(&event).await?;
        // MIP-00 key package relay list, so peers know where to find us.
        let list = EventBuilder::new(Kind::Custom(10051), "")
            .tag(Tag::custom(
                TagKind::custom("relay"),
                [self.relay.to_string()],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| e.to_string())?;
        self.publish(&list).await?;
        Ok(json!({ "event": event }))
    }

    async fn accept_welcomes(&mut self) -> Result<Value, String> {
        let filter = Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(self.keys.public_key());
        let wraps = self
            .client
            .fetch_events(filter, FETCH_TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;
        let mut groups = Vec::new();
        let mut errors = Vec::new();
        for wrap in wraps.iter() {
            let unwrapped = match self.client.unwrap_gift_wrap(wrap).await {
                Ok(u) => u,
                Err(e) => {
                    errors.push(format!("unwrap {}: {e}", wrap.id));
                    continue;
                }
            };
            let mut rumor = unwrapped.rumor;
            if rumor.kind != Kind::MlsWelcome {
                continue;
            }
            rumor.ensure_id();
            let welcome = match self.mdk.process_welcome(&wrap.id, &rumor) {
                Ok(w) => w,
                Err(e) => {
                    errors.push(format!("process_welcome: {e}"));
                    continue;
                }
            };
            if let Err(e) = self.mdk.accept_welcome(&welcome) {
                errors.push(format!("accept_welcome: {e}"));
                continue;
            }
            if let Ok(Some(g)) = self.mdk.get_group(&welcome.mls_group_id) {
                groups.push(group_json(&self.mdk, &g));
            }
        }
        Ok(json!({ "groups": groups, "errors": errors, "gift_wraps": wraps.len() }))
    }

    async fn sync(&mut self, cmd: &Value) -> Result<Value, String> {
        let gid = group_id(cmd)?;
        let group = self
            .mdk
            .get_group(&gid)
            .map_err(|e| e.to_string())?
            .ok_or("unknown group")?;
        let filter = Filter::new().kind(Kind::MlsGroupMessage).custom_tag(
            SingleLetterTag::lowercase(Alphabet::H),
            hex::encode(group.nostr_group_id),
        );
        let events = self
            .client
            .fetch_events(filter, FETCH_TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;
        let mut fresh: Vec<Event> = events
            .into_iter()
            .filter(|e| !self.seen.contains(&e.id))
            .collect();
        fresh.sort_by_key(|e| e.created_at);
        let mut messages = Vec::new();
        let mut results = Vec::new();
        for event in fresh {
            self.seen.insert(event.id);
            match self.mdk.process_message(&event) {
                Ok(MessageProcessingResult::ApplicationMessage(m)) => {
                    results.push(json!({ "event_id": event.id, "result": "application" }));
                    messages.push(json!({
                        "sender": m.pubkey.to_hex(),
                        "content": m.content,
                        "kind": m.kind.as_u16(),
                        "created_at": m.created_at.as_secs(),
                    }));
                }
                Ok(other) => {
                    results.push(json!({ "event_id": event.id, "result": format!("{other:?}") }))
                }
                Err(e) => results.push(
                    json!({ "event_id": event.id, "result": "error", "error": e.to_string() }),
                ),
            }
        }
        let epoch = self.mdk.get_group(&gid).ok().flatten().map(|g| g.epoch);
        Ok(json!({ "messages": messages, "results": results, "epoch": epoch }))
    }

    async fn send(&mut self, cmd: &Value) -> Result<Value, String> {
        let gid = group_id(cmd)?;
        let content = cmd["content"].as_str().ok_or("missing content")?;
        let rumor = EventBuilder::new(Kind::Custom(9), content).build(self.keys.public_key());
        let event = self
            .mdk
            .create_message(&gid, rumor, None)
            .map_err(|e| e.to_string())?;
        self.publish(&event).await?;
        self.seen.insert(event.id);
        Ok(json!({ "event_id": event.id }))
    }

    async fn create_group(&mut self, cmd: &Value) -> Result<Value, String> {
        let name = cmd["name"].as_str().unwrap_or("mdk-interop").to_string();
        // Key package kinds to look up (default: current 30443 and legacy 443).
        let kinds: Vec<Kind> = match cmd["kinds"].as_array() {
            Some(list) => list
                .iter()
                .filter_map(|k| k.as_u64())
                .map(|k| Kind::from(k as u16))
                .collect(),
            None => vec![Kind::Custom(30443), Kind::MlsKeyPackage],
        };
        let mut members = Vec::new();
        let mut key_packages = Vec::new();
        for m in cmd["members"].as_array().ok_or("missing members")? {
            let pk = PublicKey::from_hex(m.as_str().ok_or("member must be a hex pubkey")?)
                .map_err(|e| e.to_string())?;
            let filter = Filter::new().kinds(kinds.iter().copied()).author(pk);
            let events = self
                .client
                .fetch_events(filter, FETCH_TIMEOUT)
                .await
                .map_err(|e| e.to_string())?;
            let newest = events
                .into_iter()
                .max_by_key(|e| e.created_at)
                .ok_or(format!("no key package for {pk}"))?;
            members.push(pk);
            key_packages.push(newest);
        }
        let mut admins = vec![self.keys.public_key()];
        admins.extend(
            members
                .iter()
                .copied()
                .filter(|_| cmd["members_are_admins"].as_bool().unwrap_or(false)),
        );
        let config = NostrGroupConfigData::new(
            name,
            "FR025-04 interop".into(),
            None,
            None,
            None,
            vec![self.relay.clone()],
            admins,
        );
        let result = self
            .mdk
            .create_group(&self.keys.public_key(), key_packages.clone(), config)
            .map_err(|e| e.to_string())?;
        // One kind 444 rumor per invitee, in key package order; gift-wrap each to its recipient (MIP-02).
        for (rumor, kp) in result.welcome_rumors.into_iter().zip(key_packages.iter()) {
            let wrap = EventBuilder::gift_wrap(&self.keys, &kp.pubkey, rumor, [])
                .await
                .map_err(|e| e.to_string())?;
            self.publish(&wrap).await?;
        }
        Ok(json!({ "group": group_json(&self.mdk, &result.group) }))
    }
}

async fn reply(out: &mut tokio::io::Stdout, value: Value) {
    let mut line = value.to_string();
    line.push('\n');
    let _ = out.write_all(line.as_bytes()).await;
    let _ = out.flush().await;
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut out = tokio::io::stdout();
    let Some(relay) = arg(&args, "--relay") else {
        eprintln!("usage: mdk-harness --relay ws://HOST:PORT [--secret HEX]");
        std::process::exit(2);
    };
    let keys = match arg(&args, "--secret") {
        Some(s) => Keys::parse(&s).expect("invalid --secret"),
        None => Keys::generate(),
    };
    let relay = RelayUrl::parse(&relay).expect("invalid --relay");
    // NIP-42: the secure relay (and the test relay's #p gate on 1059) require AUTH; nostr-sdk answers it.
    let client = Client::builder()
        .signer(keys.clone())
        .opts(ClientOptions::new().automatic_authentication(true))
        .build();
    client.add_relay(relay.clone()).await.expect("add relay");
    if let Err(e) = client
        .try_connect_relay(relay.clone(), Duration::from_secs(10))
        .await
    {
        reply(&mut out, json!({ "ready": false, "error": e.to_string() })).await;
        std::process::exit(1);
    }
    let mut peer = Peer {
        keys,
        client,
        relay,
        mdk: MDK::new(MdkMemoryStorage::default()),
        seen: HashSet::new(),
    };
    reply(
        &mut out,
        json!({ "ready": true, "pubkey": peer.keys.public_key().to_hex(), "mdk": MDK_VERSION }),
    )
    .await;

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let cmd: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                reply(
                    &mut out,
                    json!({ "ok": false, "error": format!("bad json: {e}") }),
                )
                .await;
                continue;
            }
        };
        let res = match cmd["op"].as_str().unwrap_or_default() {
            "publish_key_package" => peer.publish_key_package().await,
            "accept_welcomes" => peer.accept_welcomes().await,
            "sync" => peer.sync(&cmd).await,
            "send" => peer.send(&cmd).await,
            "create_group" => peer.create_group(&cmd).await,
            "quit" => break,
            other => Err(format!("unknown op {other:?}")),
        };
        let mut value = match res {
            Ok(v) => v,
            Err(e) => json!({ "ok": false, "error": e }),
        };
        if value.get("ok").is_none() {
            value["ok"] = json!(true);
        }
        if let Some(id) = cmd.get("id") {
            value["id"] = id.clone();
        }
        reply(&mut out, value).await;
    }
    peer.client.disconnect().await;
}
