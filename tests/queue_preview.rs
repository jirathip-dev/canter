//! Issue #84 acceptance tests: the deterministic, effect-free queue preview.
//!
//! Every test drives the public `canter::queue_preview` surface over a real
//! `canter::state::State` opened in a per-test temp dir (the same fixture
//! pattern as `tests/board_read_model.rs`) and synthetic identities only —
//! nothing touches host state, a real session, the network or a subprocess.
//! Raw exits are asserted directly; the digest is recomputed from the
//! rendered bound-input document so the binding is pinned to the bytes.

use std::path::PathBuf;

use canter::board::work_item_id;
use canter::canonical::{canonical_bytes, sha256_hex};
use canter::config::{PROFILE_SECRET_UNSET, ProfileBinding, load_config};
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_preview::{
    Boundary, ITEM_STATUSES, NO_EFFECTS_STATEMENT, PlannedStep, QueuePreview, QueueRequest,
    SelectedIssue, confirm, digest_of, holds, preview_queue,
};
use canter::state::{Retention, State};
use canter::value::{Val, null, object, string};

// ---------------------------------------------------------------------------
// Fixture: isolated durable state + config
// ---------------------------------------------------------------------------

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("hf-queue-preview-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        Fixture { dir }
    }

    fn db(&self) -> PathBuf {
        self.dir.join("state.db")
    }

    fn open(&self) -> State {
        State::open(&self.db(), Retention::default()).expect("open state")
    }
}

const REPO: &str = "example-org/widgets";
const REVISION_A: &str = "1111111111111111111111111111111111111111";
const REVISION_B: &str = "2222222222222222222222222222222222222222";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";
const SECRET_DIGEST: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/// One validated `hf-profile-binding/v1` document (the same shape
/// `config show --json` presents) with the declared credential entries.
fn binding_doc(secrets: &[(&str, &str)]) -> Val {
    let mut binding = ProfileBinding {
        key: "lane-1".to_string(),
        kind: "pi".to_string(),
        provider: "provider-a".to_string(),
        model: "model-a".to_string(),
        fallbacks: Vec::new(),
        configured_limits: Vec::new(),
        introspection: false,
        secrets: secrets
            .iter()
            .map(|(name, digest)| ((*name).to_string(), (*digest).to_string()))
            .collect(),
        revision: String::new(),
    };
    binding.revision = binding.revision_of();
    binding.to_doc()
}

fn selected(id: &str, title: Option<&str>, revision: &str, requires: &[&str]) -> SelectedIssue {
    SelectedIssue {
        id: id.to_string(),
        title: title.map(str::to_string),
        revision: revision.to_string(),
        requires: requires.iter().map(|item| (*item).to_string()).collect(),
    }
}

fn step(id: &str, kind: &str, params: Option<Val>) -> PlannedStep {
    PlannedStep {
        id: id.to_string(),
        kind: kind.to_string(),
        params,
    }
}

fn resolved_params() -> Val {
    object(vec![("ref", string("staging"))])
}

/// A clean request: every attestation present, one eligible selected issue,
/// one resolved step, a staging completion boundary.
fn base_request() -> QueueRequest {
    QueueRequest {
        repository: REPO.to_string(),
        host: "host-1".to_string(),
        host_available: Some(true),
        harness_key: "lane-1".to_string(),
        harness_lanes: Some(0),
        caps: ConcurrencyCaps {
            global: 4,
            per_repository: 2,
            per_harness: 2,
        },
        workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
        workflow_hash: WORKFLOW_HASH.to_string(),
        role_config: binding_doc(&[("PROVIDER_TOKEN", SECRET_DIGEST)]),
        boundary: Boundary {
            phase: "merge".to_string(),
            integration_branch: "staging".to_string(),
            completion_branch: "staging".to_string(),
            caps: vec!["read".to_string(), "merge".to_string()],
        },
        steps: vec![step("p1", "checkout", Some(resolved_params()))],
        selected: vec![selected("5", None, REVISION_A, &[])],
    }
}

fn render(state: &State, request: &QueueRequest) -> QueuePreview {
    preview_queue(state, request).expect("preview")
}

fn array<'a>(value: &'a Val, key: &str) -> &'a Vec<Val> {
    value
        .get(key)
        .and_then(Val::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn strings(value: &Val) -> Vec<String> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|item| item.as_str().expect("string").to_string())
        .collect()
}

fn codes(holds: &[Val]) -> Vec<String> {
    holds
        .iter()
        .map(|hold| {
            hold.get("code")
                .and_then(Val::as_str)
                .expect("code")
                .to_string()
        })
        .collect()
}

/// The rendered item holds of one item (by identity), their codes.
fn item_codes(doc: &Val, id: &str) -> Vec<String> {
    for item in array(doc, "items") {
        if item.get("id").and_then(Val::as_str) == Some(id) {
            return codes(array(item, "holds"));
        }
    }
    panic!("no item {id}");
}

fn item_status(doc: &Val, id: &str) -> String {
    for item in array(doc, "items") {
        if item.get("id").and_then(Val::as_str) == Some(id) {
            return item
                .get("status")
                .and_then(Val::as_str)
                .expect("status")
                .to_string();
        }
    }
    panic!("no item {id}");
}

fn top_codes(doc: &Val) -> Vec<String> {
    codes(array(doc, "holds"))
}

// ---------------------------------------------------------------------------
// Durable state seeds (synthetic; the same grant/instance path the daemon
// uses, so ownership facts are real durable rows)
// ---------------------------------------------------------------------------

fn seed_run(state: &State, issue: i64, revision: &str, run: &str) -> String {
    seed_run_with_scope(
        state,
        issue,
        revision,
        &format!("worktrees/issues/{issue}"),
        run,
    )
}

/// Seed one grant and one run with an explicit declared monorepo scope.
fn seed_run_with_scope(
    state: &State,
    issue: i64,
    revision: &str,
    scope: &str,
    run: &str,
) -> String {
    let epoch = state.summary().expect("summary").0;
    let grant_id = format!("gr_{}", &sha256_hex(run.as_bytes())[..16]);
    let doc = Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"{grant_id}","repository":"{REPO}",
            "issue":{{"number":{issue},"revision":"{revision}"}},
            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
            "phase":"merge","scope":"{scope}",
            "caps":["read","worktree","spawn","review","merge"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":{epoch},
            "created_at":"2026-09-06T00:00:00Z"}}"#
    ))
    .expect("grant document");
    state.issue_grant(&doc).expect("issue grant");
    state
        .start_instance(run, &grant_id, DOCTRINE_WORKFLOW_ID, "2026-09-06T00:00:00Z")
        .expect("start instance");
    run.to_string()
}

// ---------------------------------------------------------------------------
// AC1 - stable identities, dedupe, digest bindings
// ---------------------------------------------------------------------------

#[test]
fn identities_normalize_and_dedupe_on_the_stable_form_never_on_titles() {
    let fixture = Fixture::new("identity");
    let state = fixture.open();

    // The same identity presented three times (different case, bare number,
    // different titles) collapses to ONE item.
    let mut doubled = base_request();
    doubled.selected = vec![
        selected(
            "EXAMPLE-ORG/Widgets#5",
            Some("First title"),
            REVISION_A,
            &[],
        ),
        selected(
            "example-org/widgets#5",
            Some("Renamed since"),
            REVISION_A,
            &[],
        ),
        selected("5", None, REVISION_A, &[]),
    ];
    let merged = render(&state, &doubled);
    assert_eq!(array(&merged.doc, "items").len(), 1, "one stable identity");
    let item = &array(&merged.doc, "items")[0];
    assert_eq!(
        item.get("id").and_then(Val::as_str),
        Some("example-org/widgets#5")
    );
    assert_eq!(
        item.get("work_item").and_then(Val::as_str),
        Some(work_item_id("example-org/widgets", 5).as_str()),
        "the stable work-item identity is derived from the normalized identity"
    );

    // Reordering and titles never move the digest; the selection does.
    let single = render(&state, &base_request());
    assert_eq!(
        merged.digest, single.digest,
        "duplicate presentations of one identity normalize to the same bound inputs"
    );
    let mut retitled = base_request();
    retitled.selected = vec![selected("5", Some("A different title"), REVISION_A, &[])];
    assert_eq!(
        render(&state, &retitled).digest,
        single.digest,
        "titles are display text and never enter the digest"
    );

    // Two DIFFERENT issues sharing one title stay two items.
    let mut twins = base_request();
    twins.selected = vec![
        selected("5", Some("Shared title"), REVISION_A, &[]),
        selected("6", Some("Shared title"), REVISION_A, &[]),
    ];
    assert_eq!(array(&render(&state, &twins).doc, "items").len(), 2);
}

#[test]
fn same_inputs_yield_identical_bytes_and_digest_and_the_digest_binds_the_rendered_inputs() {
    let fixture = Fixture::new("determinism");
    let state = fixture.open();
    let mut request = base_request();
    request.selected = vec![
        selected("7", Some("Seven"), REVISION_A, &["5"]),
        selected("5", None, REVISION_B, &[]),
    ];
    let first = render(&state, &request);
    let second = render(&state, &request);
    assert_eq!(
        canonical_bytes(&first.doc),
        canonical_bytes(&second.doc),
        "identical inputs render identical canonical bytes"
    );
    assert_eq!(first.digest, second.digest);
    let bound = first.doc.get("request").expect("request");
    assert_eq!(
        first.digest,
        digest_of(bound),
        "the digest is sha256 over the canonical bytes of the rendered bound inputs"
    );
    assert_eq!(first.digest.len(), 64);
    // The bound input document carries exactly the required bindings.
    assert_eq!(bound.get("repository").and_then(Val::as_str), Some(REPO));
    assert_eq!(bound.get("host").and_then(Val::as_str), Some("host-1"));
    let workflow = bound.get("workflow").expect("workflow");
    assert_eq!(
        workflow.get("id").and_then(Val::as_str),
        Some(DOCTRINE_WORKFLOW_ID)
    );
    assert_eq!(
        workflow.get("hash").and_then(Val::as_str),
        Some(WORKFLOW_HASH)
    );
    let role_config = bound.get("role_config").expect("role_config");
    assert_eq!(role_config.get("key").and_then(Val::as_str), Some("lane-1"));
    assert!(
        role_config
            .get("revision")
            .and_then(Val::as_str)
            .is_some_and(|revision| revision.len() == 64),
        "the role-configuration revision is bound"
    );
    let boundary = bound.get("boundary").expect("boundary");
    assert_eq!(boundary.get("phase").and_then(Val::as_str), Some("merge"));
    assert_eq!(
        boundary.get("completion_branch").and_then(Val::as_str),
        Some("staging")
    );
    let selected = array(bound, "selected");
    assert_eq!(selected.len(), 2);
    assert_eq!(
        selected[0].get("id").and_then(Val::as_str),
        Some("example-org/widgets#5"),
        "the bound selection is sorted by normalized identity"
    );
    assert_eq!(
        strings(selected[1].get("requires").expect("requires")),
        vec!["example-org/widgets#5".to_string()]
    );
    assert_eq!(
        selected[1].get("revision").and_then(Val::as_str),
        Some(REVISION_A),
        "the selected spec revision is bound"
    );
}

#[test]
fn input_changes_move_the_digest_and_invalidate_a_stale_approval() {
    let fixture = Fixture::new("invalidate");
    let state = fixture.open();
    let base = render(&state, &base_request());
    assert!(
        confirm(&base, &base.digest).is_ok(),
        "the current digest authorizes"
    );

    let mut changes: Vec<(&str, QueueRequest)> = Vec::new();
    let mut revision = base_request();
    revision.selected = vec![selected("5", None, REVISION_B, &[])];
    changes.push(("revision", revision));
    let mut host = base_request();
    host.host = "host-2".to_string();
    changes.push(("host", host));
    let mut role = base_request();
    role.role_config = binding_doc(&[(
        "PROVIDER_TOKEN",
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    )]);
    changes.push(("role-config revision", role));
    let mut workflow = base_request();
    workflow.workflow_hash =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    changes.push(("workflow", workflow));
    let mut boundary = base_request();
    boundary.boundary.phase = "review".to_string();
    changes.push(("boundary", boundary));
    let mut selection = base_request();
    selection.selected = vec![
        selected("5", None, REVISION_A, &[]),
        selected("6", None, REVISION_A, &[]),
    ];
    changes.push(("selection", selection));
    let mut dependency = base_request();
    dependency.selected = vec![
        selected("5", None, REVISION_A, &[]),
        selected("6", None, REVISION_A, &["5"]),
    ];
    changes.push(("dependency edge", dependency));
    let mut steps = base_request();
    steps.steps = vec![step(
        "p1",
        "checkout",
        Some(object(vec![("ref", string("integration"))])),
    )];
    changes.push(("step binding", steps));

    for (label, changed) in changes {
        let moved = render(&state, &changed);
        assert_ne!(
            base.digest, moved.digest,
            "{label} change must move the digest"
        );
        let refusal = confirm(&base, &moved.digest).expect_err("stale approval refuses");
        assert_eq!(refusal.code, "refusal.plan.stale");
    }
}

// ---------------------------------------------------------------------------
// AC2 - dependency order, eligibility, unresolved dependencies, concurrency
// ---------------------------------------------------------------------------

#[test]
fn dependency_order_and_statuses_are_shown_and_unresolved_dependencies_are_never_scoped() {
    let fixture = Fixture::new("deps");
    let state = fixture.open();
    let mut request = base_request();
    request.selected = vec![
        selected("9", None, REVISION_A, &["500"]),
        selected("6", None, REVISION_A, &["5"]),
        selected("8", None, REVISION_A, &["9"]),
        selected("5", None, REVISION_A, &[]),
    ];
    let preview = render(&state, &request);
    let doc = &preview.doc;
    let ids: Vec<String> = array(doc, "items")
        .iter()
        .map(|item| item.get("id").and_then(Val::as_str).unwrap().to_string())
        .collect();
    assert_eq!(
        ids,
        vec![
            "example-org/widgets#5".to_string(),
            "example-org/widgets#6".to_string(),
            "example-org/widgets#9".to_string(),
            "example-org/widgets#8".to_string(),
        ],
        "items appear in dependency order: every required dependency precedes its dependent"
    );
    assert_eq!(item_status(doc, "example-org/widgets#5"), "eligible");
    assert_eq!(item_status(doc, "example-org/widgets#6"), "eligible");
    // 9 requires D, which is not selected: the item is blocked and D is
    // never silently added to the selected scope.
    assert_eq!(item_status(doc, "example-org/widgets#9"), "blocked");
    assert_eq!(
        item_codes(doc, "example-org/widgets#9"),
        vec![holds::DEPENDENCY_UNRESOLVED.to_string()]
    );
    // 8 depends on the blocked 9: it is blocked in turn.
    assert_eq!(item_status(doc, "example-org/widgets#8"), "blocked");
    assert_eq!(
        item_codes(doc, "example-org/widgets#8"),
        vec![holds::DEPENDENCY_UNSETTLED.to_string()]
    );
    assert_eq!(
        array(doc, "items").len(),
        4,
        "D is shown as an unresolved requirement, never as a selected item"
    );
    for item in array(doc, "items") {
        let status = item.get("status").and_then(Val::as_str).expect("status");
        assert!(
            ITEM_STATUSES.contains(&status),
            "every rendered status is in the closed set: {status}"
        );
    }
    assert!(
        !preview.ready,
        "blocked items keep the preview from reading ready"
    );
}

#[test]
fn cross_repository_identities_are_linked_requirements_not_selected_scope() {
    let fixture = Fixture::new("crossrepo");
    let state = fixture.open();
    let mut request = base_request();
    request.selected = vec![selected("5", None, REVISION_A, &["Other-Org/Gadgets#7"])];
    let preview = render(&state, &request);
    let doc = &preview.doc;
    assert_eq!(array(doc, "items").len(), 1);
    assert_eq!(item_status(doc, "example-org/widgets#5"), "blocked");
    assert_eq!(
        item_codes(doc, "example-org/widgets#5"),
        vec![holds::DEPENDENCY_UNRESOLVED.to_string()]
    );
    let requires = strings(array(doc, "items")[0].get("requires").expect("requires"));
    assert_eq!(
        requires,
        vec!["other-org/gadgets#7".to_string()],
        "cross-repository references are normalized linked requirements"
    );
    let held = array(doc, "holds")
        .iter()
        .chain(array(&array(doc, "items")[0], "holds").iter())
        .map(|hold| {
            hold.get("message")
                .and_then(Val::as_str)
                .unwrap()
                .to_string()
        })
        .collect::<Vec<String>>()
        .join("\n");
    assert!(
        held.contains("other-org/gadgets#7"),
        "the unresolved dependency is named: {held}"
    );

    // A cross-repository issue can never be SELECTED scope for this run.
    let mut outside = base_request();
    outside.selected = vec![selected("other-org/gadgets#7", None, REVISION_A, &[])];
    let refusal = preview_queue(&state, &outside).expect_err("outside scope refuses");
    assert_eq!(refusal.code, "usage.queue_scope");
}

#[test]
fn cycles_are_detected_and_named_never_ordered_as_ready() {
    let fixture = Fixture::new("cycles");
    let state = fixture.open();
    let mut request = base_request();
    request.selected = vec![
        selected("5", None, REVISION_A, &["6"]),
        selected("6", None, REVISION_A, &["5"]),
        selected("7", None, REVISION_A, &["5"]),
    ];
    let preview = render(&state, &request);
    let doc = &preview.doc;
    assert_eq!(item_status(doc, "example-org/widgets#5"), "blocked");
    assert_eq!(item_status(doc, "example-org/widgets#6"), "blocked");
    assert_eq!(
        item_codes(doc, "example-org/widgets#5"),
        vec![holds::DEPENDENCY_CYCLE.to_string()]
    );
    assert_eq!(
        item_codes(doc, "example-org/widgets#6"),
        vec![holds::DEPENDENCY_CYCLE.to_string()]
    );
    // 7 depends on the cycle but is not part of it.
    assert_eq!(
        item_codes(doc, "example-org/widgets#7"),
        vec![holds::DEPENDENCY_UNSETTLED.to_string()]
    );
    assert!(!preview.ready);
    // Cycle members and their dependents render last, in identity order.
    let ids: Vec<String> = array(doc, "items")
        .iter()
        .map(|item| item.get("id").and_then(Val::as_str).unwrap().to_string())
        .collect();
    assert_eq!(
        ids,
        vec![
            "example-org/widgets#5".to_string(),
            "example-org/widgets#6".to_string(),
            "example-org/widgets#7".to_string(),
        ]
    );
}

#[test]
fn ownership_and_stale_revisions_are_reported_from_durable_state() {
    let fixture = Fixture::new("owned");
    let state = fixture.open();
    seed_run(&state, 5, REVISION_A, "run-owned-0001");

    // The recorded revision matches: already owned, no stale hold.
    let matching = render(&state, &base_request());
    let doc = &matching.doc;
    assert_eq!(item_status(doc, "example-org/widgets#5"), "already_owned");
    assert!(item_codes(doc, "example-org/widgets#5").is_empty());
    let owned = array(doc, "items")[0].get("owned").expect("owned");
    assert_eq!(
        owned.get("instance_id").and_then(Val::as_str),
        Some("run-owned-0001")
    );
    assert_eq!(
        owned.get("issue_revision").and_then(Val::as_str),
        Some(REVISION_A)
    );
    assert!(
        matching.ready,
        "an owned item with no moved binding is reported without holds"
    );

    // The selected spec revision moved past the recorded run revision.
    let mut moved = base_request();
    moved.selected = vec![selected("5", None, REVISION_B, &[])];
    let preview = render(&state, &moved);
    assert_eq!(
        item_status(&preview.doc, "example-org/widgets#5"),
        "already_owned"
    );
    assert_eq!(
        item_codes(&preview.doc, "example-org/widgets#5"),
        vec![holds::REVISION_STALE.to_string()]
    );
    assert!(!preview.ready);

    // Ownership never hides a declared dependency fact: an owned item with
    // an out-of-scope requirement still reports the unresolved dependency.
    let mut undeclared = base_request();
    undeclared.selected = vec![selected("5", None, REVISION_A, &["500"])];
    let preview = render(&state, &undeclared);
    assert_eq!(
        item_status(&preview.doc, "example-org/widgets#5"),
        "already_owned"
    );
    assert_eq!(
        item_codes(&preview.doc, "example-org/widgets#5"),
        vec![holds::DEPENDENCY_UNRESOLVED.to_string()]
    );
    assert!(!preview.ready);

    // A paused run still owns its issue (a second run cannot start), while
    // the fan-out gate's counted set excludes paused lanes: ownership never
    // disappears with a pause, and the concurrency counts mirror the gate.
    state
        .pause_instance("run-owned-0001", &"a".repeat(64), "2026-09-06T01:00:00Z")
        .expect("pause instance");
    let paused = render(&state, &base_request());
    assert_eq!(
        item_status(&paused.doc, "example-org/widgets#5"),
        "already_owned"
    );
    assert_eq!(
        paused
            .doc
            .get("concurrency")
            .and_then(|concurrency| concurrency.get("running"))
            .and_then(|running| running.get("repository"))
            .and_then(Val::as_int),
        Some(0),
        "the gate's counted set excludes paused lanes"
    );
}

#[test]
fn concurrency_is_shown_and_exhausted_capacities_are_named_holds() {
    let fixture = Fixture::new("concurrency");
    let state = fixture.open();
    seed_run(&state, 5, REVISION_A, "run-cap-0001");
    seed_run(&state, 6, REVISION_A, "run-cap-0002");

    let mut request = base_request();
    request.selected = vec![selected("7", None, REVISION_A, &[])];
    request.harness_lanes = Some(2);
    let preview = render(&state, &request);
    let doc = &preview.doc;
    let top = top_codes(doc);
    assert!(
        top.contains(&"refusal.admission.cap_repository".to_string()),
        "the per-repository cap is exhausted: {top:?}"
    );
    assert!(
        top.contains(&"refusal.admission.cap_harness".to_string()),
        "the attested per-harness occupancy is exhausted: {top:?}"
    );
    let concurrency = doc.get("concurrency").expect("concurrency");
    let running = concurrency.get("running").expect("running");
    assert_eq!(running.get("total").and_then(Val::as_int), Some(2));
    assert_eq!(running.get("repository").and_then(Val::as_int), Some(2));
    assert_eq!(running.get("harness_lanes").and_then(Val::as_int), Some(2));
    let lanes = array(concurrency, "lanes");
    assert_eq!(
        lanes.len(),
        2,
        "the active same-repository lanes are rendered"
    );
    assert_eq!(
        lanes[0].get("id").and_then(Val::as_str),
        Some("example-org/widgets#5")
    );
    assert!(!preview.ready);

    // A lane holding an overlapping monorepo scope refuses fan-out.
    let mut overlap = base_request();
    overlap.selected = vec![selected("9", None, REVISION_A, &[])];
    overlap.harness_lanes = Some(0);
    overlap.caps = ConcurrencyCaps {
        global: 8,
        per_repository: 4,
        per_harness: 4,
    };
    let overlapping = render(&state, &overlap);
    assert!(
        !top_codes(&overlapping.doc).contains(&"refusal.admission.monorepo_overlap".to_string()),
        "a lane of another issue does not overlap worktrees/issues/9"
    );

    // A concurrent lane whose declared scope DOES overlap the planned scope
    // refuses fan-out with the named admission hold.
    seed_run_with_scope(&state, 8, REVISION_A, "worktrees/issues/9", "run-cap-0003");
    let overlapping = render(&state, &overlap);
    let top = top_codes(&overlapping.doc);
    assert!(
        top.contains(&"refusal.admission.monorepo_overlap".to_string()),
        "an overlapping declared monorepo path refuses fan-out: {top:?}"
    );
    assert!(!overlapping.ready);
}

// ---------------------------------------------------------------------------
// AC3 - named holds: unknown occupancy, unsupported steps, missing auth,
// unavailable host
// ---------------------------------------------------------------------------

#[test]
fn unknown_occupancy_unavailable_host_and_missing_auth_are_named_holds_not_readiness() {
    let fixture = Fixture::new("holds");
    let state = fixture.open();

    // Unknown occupancy, unknown host availability, an unset credential.
    let mut blocked = base_request();
    blocked.harness_lanes = None;
    blocked.host_available = None;
    blocked.role_config = binding_doc(&[("PROVIDER_TOKEN", PROFILE_SECRET_UNSET)]);
    let preview = render(&state, &blocked);
    let top = top_codes(&preview.doc);
    assert!(
        top.contains(&holds::OCCUPANCY_UNKNOWN.to_string()),
        "{top:?}"
    );
    assert!(
        top.contains(&holds::HOST_UNAVAILABLE.to_string()),
        "{top:?}"
    );
    assert!(top.contains(&holds::AUTH_MISSING.to_string()), "{top:?}");
    assert!(!preview.ready, "holds are never apparent readiness");

    // An attested-unavailable host is a hold with the same code.
    let mut unavailable = base_request();
    unavailable.host_available = Some(false);
    let preview = render(&state, &unavailable);
    let top = top_codes(&preview.doc);
    assert!(
        top.contains(&holds::HOST_UNAVAILABLE.to_string()),
        "{top:?}"
    );
    assert!(!preview.ready);

    // Positive control: every attestation present, credential set.
    let clean = render(&state, &base_request());
    let top = top_codes(&clean.doc);
    for code in [
        holds::OCCUPANCY_UNKNOWN,
        holds::HOST_UNAVAILABLE,
        holds::AUTH_MISSING,
    ] {
        assert!(!top.contains(&code.to_string()), "clean preview: {top:?}");
    }
    assert!(clean.ready, "a fully attested preview reads ready: {top:?}");
}

#[test]
fn unsupported_and_unresolved_executable_steps_are_named_holds() {
    let fixture = Fixture::new("steps");
    let state = fixture.open();
    let mut request = base_request();
    request.steps = vec![
        step("p1", "harness_start", None),
        step("p2", "shell", Some(resolved_params())),
        step("p3", "checkout", Some(resolved_params())),
    ];
    let preview = render(&state, &request);
    let doc = &preview.doc;
    let top = array(doc, "holds");
    let pairs: Vec<(String, String)> = top
        .iter()
        .map(|hold| {
            (
                hold.get("code").and_then(Val::as_str).unwrap().to_string(),
                hold.get("subject")
                    .and_then(Val::as_str)
                    .unwrap()
                    .to_string(),
            )
        })
        .collect();
    assert!(
        pairs.contains(&(holds::STEP_UNRESOLVED.to_string(), "p1".to_string())),
        "{pairs:?}"
    );
    assert!(
        pairs.contains(&(holds::STEP_UNSUPPORTED.to_string(), "p2".to_string())),
        "{pairs:?}"
    );
    let steps = array(doc, "steps");
    assert_eq!(steps[0].get("supported").and_then(Val::as_bool), Some(true));
    assert_eq!(steps[0].get("resolved").and_then(Val::as_bool), Some(false));
    assert_eq!(
        steps[1].get("supported").and_then(Val::as_bool),
        Some(false)
    );
    assert_eq!(steps[2].get("supported").and_then(Val::as_bool), Some(true));
    assert_eq!(steps[2].get("resolved").and_then(Val::as_bool), Some(true));
    assert!(!preview.ready);

    // An unsupported workflow pin is a named hold too (its executable steps
    // cannot be planned) and is never presented as ready.
    let mut workflow = base_request();
    workflow.workflow_id = "some-other-engine".to_string();
    workflow.steps = vec![step("p1", "checkout", Some(resolved_params()))];
    let preview = render(&state, &workflow);
    assert!(top_codes(&preview.doc).contains(&holds::WORKFLOW_UNSUPPORTED.to_string()));
    assert!(!preview.ready);
}

// ---------------------------------------------------------------------------
// Issue #210: per-leg lane identity is unique by construction
// ---------------------------------------------------------------------------

/// One `review_evidence` step that declares the reviewer leg (issue #193) and
/// the lane checkout IT binds for that leg (issue #210).
fn reviewer_leg_step(worktree: &str, execution: &str) -> PlannedStep {
    let mut binding = ProfileBinding {
        key: "lane-rev".to_string(),
        kind: "hermes".to_string(),
        provider: "provider-rev".to_string(),
        model: "model-rev".to_string(),
        fallbacks: Vec::new(),
        configured_limits: Vec::new(),
        introspection: false,
        secrets: Vec::new(),
        revision: String::new(),
    };
    binding.revision = binding.revision_of();
    step(
        "p6-5",
        "review_evidence",
        Some(object(vec![
            ("execution", string(execution)),
            ("harness_key", string("lane-rev")),
            ("kind", string("hermes")),
            ("reviewer_profile", binding.to_doc()),
            ("worktree", string(worktree)),
        ])),
    )
}

/// W2 (issue #210): a plan that would bind TWO legs to ONE lane checkout —
/// the measured live shape, a reviewer leg declaring the implementer lane's
/// checkout — is refused at PREVIEW time with a typed code naming both
/// identities. It is never discovered at dispatch time by the substrate as
/// `refusal.lane.name_collision`.
#[test]
fn a_plan_that_would_bind_two_legs_to_one_lane_checkout_is_refused_at_preview_time() {
    let fixture = Fixture::new("lane-collision");
    let state = fixture.open();
    let mut request = base_request();
    request.steps = vec![
        step("p1", "checkout", Some(resolved_params())),
        step(
            "p4-5",
            "prompt",
            Some(object(vec![
                ("worktree", string("issues-5")),
                ("branch", string("issue-5")),
            ])),
        ),
        reviewer_leg_step("issues-5", "herdr"),
    ];
    let error = preview_queue(&state, &request)
        .expect_err("a plan that would collide two legs on one checkout refuses");
    assert_eq!(error.code, "usage.queue_lane_identity", "{}", error.message);
    // The refusal names BOTH identities: the reviewer leg's own lane and the
    // implementer leg that owns the checkout the step would bind.
    for needle in [
        "\"rev-5-r1\"",
        "\"5-rev1\"",
        "issues-5-rev1",
        "\"impl-5\"",
        "\"5-impl\"",
        "issues-5",
    ] {
        assert!(
            error.message.contains(needle),
            "the refusal names {needle}: {}",
            error.message
        );
    }

    // A checkout that is no leg's lane refuses too — never a silent pane at
    // an unbound path.
    request.steps.pop();
    request
        .steps
        .push(reviewer_leg_step("issues-5-somewhere", "herdr"));
    let error = preview_queue(&state, &request)
        .expect_err("a checkout no leg derives refuses before submission");
    assert_eq!(error.code, "usage.queue_lane_identity", "{}", error.message);

    // The positive control: the SAME step binding the reviewer leg's OWN lane
    // renders, and the rendered plan carries the derivation (issue #210
    // legibility) for the reviewer leg AND for the implementer leg.
    request.steps.pop();
    request
        .steps
        .push(reviewer_leg_step("issues-5-rev1", "herdr"));
    let preview = render(&state, &request);
    let steps = array(&preview.doc, "steps");
    let lane_of = |id: &str| -> Val {
        steps
            .iter()
            .find(|step| step.get("id").and_then(Val::as_str) == Some(id))
            .and_then(|step| step.get("lane").cloned())
            .unwrap_or_else(|| panic!("step {id} renders with its lane identity: {steps:?}"))
    };
    let reviewer = lane_of("p6-5");
    assert_eq!(reviewer.get("role").and_then(Val::as_str), Some("reviewer"));
    assert_eq!(reviewer.get("round").and_then(Val::as_int), Some(1));
    assert_eq!(
        reviewer.get("agent").and_then(Val::as_str),
        Some("rev-5-r1")
    );
    assert_eq!(
        reviewer.get("workspace").and_then(Val::as_str),
        Some("5-rev1")
    );
    assert_eq!(
        reviewer.get("checkout").and_then(Val::as_str),
        Some("issues-5-rev1")
    );
    let implementer = lane_of("p4-5");
    assert_eq!(
        implementer.get("role").and_then(Val::as_str),
        Some("implementer")
    );
    assert_eq!(
        implementer.get("agent").and_then(Val::as_str),
        Some("impl-5")
    );
    assert_eq!(
        implementer.get("workspace").and_then(Val::as_str),
        Some("5-impl")
    );
    assert_eq!(
        implementer.get("checkout").and_then(Val::as_str),
        Some("issues-5")
    );
    assert_ne!(
        reviewer, implementer,
        "the reviewer leg's lane identity is distinct by construction"
    );

    // The bare-subprocess fallback has no lane registration: the rule is the
    // pane substrate's, and the fallback keeps the run's lane checkout.
    request.steps.pop();
    request
        .steps
        .push(reviewer_leg_step("issues-5", "headless"));
    let preview = render(&state, &request);
    let steps = array(&preview.doc, "steps");
    let headless = steps
        .iter()
        .find(|step| step.get("id").and_then(Val::as_str) == Some("p6-5"))
        .expect("the headless review step renders");
    assert_eq!(
        headless
            .get("lane")
            .and_then(|lane| lane.get("role"))
            .and_then(Val::as_str),
        Some("implementer"),
        "the fallback binds the run's lane checkout, unchanged: {headless:?}"
    );
}

#[test]
fn protected_branch_and_production_boundaries_are_named_holds() {
    let fixture = Fixture::new("branch");
    let state = fixture.open();

    let mut protected = base_request();
    protected.boundary.completion_branch = "main".to_string();
    let preview = render(&state, &protected);
    assert!(
        top_codes(&preview.doc).contains(&holds::PROTECTED_BRANCH.to_string()),
        "a production-branch completion never reads ready"
    );
    assert!(!preview.ready);

    let mut production = base_request();
    production.boundary.phase = "production".to_string();
    production.boundary.caps = vec!["read".to_string(), "production".to_string()];
    let preview = render(&state, &production);
    assert!(
        top_codes(&preview.doc).contains(&"refusal.policy.production_confirmation".to_string()),
        "a production boundary reuses the human-only production gate"
    );
    assert!(!preview.ready);

    let clean = render(&state, &base_request());
    assert!(clean.ready);
}

// ---------------------------------------------------------------------------
// AC4 - no effects, determinism of the rendered boundaries
// ---------------------------------------------------------------------------

#[test]
fn the_preview_has_no_effects_and_reads_only_the_durable_state_store() {
    // Static surface scan: the preview module cannot spawn a process or
    // reach the network, and its only durable surface is the read API.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source =
        std::fs::read_to_string(root.join("src/queue_preview.rs")).expect("read queue_preview.rs");
    for banned in [
        "std::process",
        "Command",
        "std::net",
        "TcpStream",
        "UnixStream",
        "std::fs",
        "remote::",
        "adapters::",
        "client::",
        "daemon::",
        ".spawn(",
        "start_instance",
        "issue_grant",
        "record_evidence",
        "pause_instance",
        "resume_instance",
        "append_audit",
        "rotate_epoch",
    ] {
        assert!(
            !source.contains(banned),
            "src/queue_preview.rs must not reference {banned}: the preview is an effect-free projection"
        );
    }

    // Behavioural pin: repeated previews leave the durable state and the
    // state file bytes untouched, and the rendered boundaries say so.
    let fixture = Fixture::new("noeffects");
    let state = fixture.open();
    seed_run(&state, 5, REVISION_A, "run-noeffects-0001");
    let before_bytes = std::fs::read(fixture.db()).expect("db bytes");
    let before_digest = sha256_hex(&before_bytes);
    let before_summary = state.summary().expect("summary before");

    let mut request = base_request();
    request.selected = vec![
        selected("5", None, REVISION_A, &[]),
        selected("6", None, REVISION_A, &["5"]),
    ];
    for _ in 0..2 {
        let preview = render(&state, &request);
        let boundaries = preview.doc.get("boundaries").expect("boundaries");
        for flag in ["mutates", "spawns", "grants", "persists", "resumes"] {
            assert_eq!(
                boundaries.get(flag).and_then(Val::as_bool),
                Some(false),
                "boundaries.{flag} must be false"
            );
        }
        assert_eq!(
            boundaries.get("statement").and_then(Val::as_str),
            Some(NO_EFFECTS_STATEMENT)
        );
    }
    let after_summary = state.summary().expect("summary after");
    assert_eq!(
        before_summary, after_summary,
        "a preview must not journal, rotate or claim anything"
    );
    let after_bytes = std::fs::read(fixture.db()).expect("db bytes after");
    assert_eq!(
        before_digest,
        sha256_hex(&after_bytes),
        "a preview must not write to the state database"
    );
}

// ---------------------------------------------------------------------------
// Refusals and config-sourced identities
// ---------------------------------------------------------------------------

#[test]
fn malformed_requests_and_tampered_bindings_are_refused() {
    let fixture = Fixture::new("refusals");
    let state = fixture.open();

    let cases: Vec<(&str, QueueRequest)> = vec![
        ("scope", {
            let mut request = base_request();
            request.selected = vec![selected("other-org/gadgets#1", None, REVISION_A, &[])];
            request
        }),
        ("issue", {
            let mut request = base_request();
            request.selected = vec![selected("5", None, "not-a-revision", &[])];
            request
        }),
        ("conflict", {
            let mut request = base_request();
            request.selected = vec![
                selected("5", None, REVISION_A, &[]),
                selected("5", None, REVISION_B, &[]),
            ];
            request
        }),
        ("selected", {
            let mut request = base_request();
            request.selected = Vec::new();
            request
        }),
        ("host", {
            let mut request = base_request();
            request.host = "host/1".to_string();
            request
        }),
        ("boundary", {
            let mut request = base_request();
            request.boundary.phase = "publish".to_string();
            request
        }),
        ("capability", {
            let mut request = base_request();
            request.boundary.caps = vec!["admin".to_string()];
            request
        }),
        ("workflow", {
            let mut request = base_request();
            request.workflow_hash = "not-a-hash".to_string();
            request
        }),
        ("steps", {
            let mut request = base_request();
            request.steps = vec![
                step("p1", "checkout", Some(resolved_params())),
                step("p1", "merge", Some(resolved_params())),
            ];
            request
        }),
        ("binding", {
            let mut request = base_request();
            let mut tampered = binding_doc(&[]);
            if let Val::Obj(fields) = &mut tampered {
                fields.insert("revision".to_string(), string(&"f".repeat(64)));
            }
            request.role_config = tampered;
            request
        }),
    ];
    for (label, request) in cases {
        let refusal = preview_queue(&state, &request).expect_err(label);
        assert!(
            refusal.code.starts_with("usage.queue_")
                || refusal.code.starts_with("refusal.profile."),
            "{label}: unexpected code {}",
            refusal.code
        );
    }
    // The tampered binding reports the existing profile-revision refusal.
    let mut tampered = base_request();
    let mut document = binding_doc(&[]);
    if let Val::Obj(fields) = &mut document {
        fields.insert("revision".to_string(), string(&"f".repeat(64)));
    }
    tampered.role_config = document;
    let refusal = preview_queue(&state, &tampered).expect_err("tampered revision");
    assert_eq!(refusal.code, "refusal.profile.revision");
}

#[test]
fn the_repository_identity_is_sourced_from_loaded_configuration() {
    let fixture = Fixture::new("config");
    let state = fixture.open();
    let config_path = fixture.dir.join("config.toml");
    std::fs::write(
        &config_path,
        "schema = \"hf-config/v1\"\n\n[repository.widgets]\norigin = \"https://example.invalid/Example-Org/Widgets\"\n",
    )
    .expect("write config");
    let config = load_config(&config_path).expect("load config");
    let repositories = config.effective_repositories();
    assert_eq!(repositories.len(), 1);
    let repository = repositories[0];

    let mut request = base_request();
    request.repository = repository.identity();
    let preview = render(&state, &request);
    let bound = preview.doc.get("request").expect("request");
    assert_eq!(
        bound.get("repository").and_then(Val::as_str),
        Some("example-org/widgets"),
        "the bound repository is the normalized configured identity"
    );

    // Identity equality is case-insensitive: a mixed-case configured
    // identity and a lowercase selection are the same identity.
    assert_eq!(
        repository.identity().to_ascii_lowercase(),
        "example-org/widgets"
    );
}

#[test]
fn concurrent_calls_with_an_identical_request_are_bit_identical() {
    // Determinism has no hidden ordering source: a 16-way re-render of the
    // same request agrees on canonical bytes and digest.
    let fixture = Fixture::new("multirender");
    let state = fixture.open();
    let mut request = base_request();
    request.selected = vec![
        selected("11", None, REVISION_A, &["10"]),
        selected("10", None, REVISION_B, &[]),
    ];
    let reference = render(&state, &request);
    for _ in 0..15 {
        let again = render(&state, &request);
        assert_eq!(canonical_bytes(&again.doc), canonical_bytes(&reference.doc));
        assert_eq!(again.digest, reference.digest);
    }
}

// Keep an explicit reference to `null` so the import list documents that the
// rendered document uses JSON null for absent facts.
#[test]
fn absent_facts_render_as_json_null_not_omitted() {
    let fixture = Fixture::new("nulls");
    let state = fixture.open();
    let preview = render(&state, &base_request());
    let item = &array(&preview.doc, "items")[0];
    assert_eq!(item.get("title"), Some(&null()));
    assert_eq!(item.get("owned"), Some(&null()));
}

#[test]
fn bound_inputs_are_a_plain_data_document() {
    // The rendered bound inputs carry no host paths and stay within the
    // public-data boundary (synthetic identities only).
    let fixture = Fixture::new("databoundary");
    let state = fixture.open();
    let preview = render(&state, &base_request());
    let text = canter::canonical::canonical_text(&preview.doc);
    // The markers are runtime-assembled: the public-tree scanner owns the
    // literal forms and this test must not carry them (its own de-shaping
    // pattern, RULE-ABS-PATH-UNIX).
    let banned = [
        format!("/{}/", "Users"),
        format!("/{}/", "home"),
        "token=".to_string(),
        "Bearer ".to_string(),
    ];
    for marker in banned {
        assert!(
            !text.contains(&marker),
            "rendered preview must not contain {marker:?}"
        );
    }
    // Sanity: the bound input document round-trips through the canonical
    // writer byte-for-byte (the digest is over stable bytes).
    let bound = preview.doc.get("request").expect("request").clone();
    let reparsed = Val::parse_json(std::str::from_utf8(&canonical_bytes(&bound)).expect("utf8"))
        .expect("parse");
    assert_eq!(canonical_bytes(&reparsed), canonical_bytes(&bound));
}
