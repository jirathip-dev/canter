//! Worktree-backed lane registration. Display names are not ownership tokens.
use super::*;

/// Deterministic display keys; the opaque session id remains a metadata token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneNames {
    /// Registered Herdr agent name.
    pub agent: String,
    /// Workspace label.
    pub workspace: String,
}

impl LaneNames {
    /// Closed roles and positive issue/round numbers prevent arbitrary names.
    pub fn new(issue: u64, role: &str, round: u64) -> Result<Self, AdapterError> {
        if issue == 0 || round == 0 || !matches!(role, "implementer" | "reviewer") {
            return Err(AdapterError::refusal(
                CODE_BAD_REQUEST,
                "lane names require a positive issue/round and implementer|reviewer role",
            ));
        }
        let (agent, workspace) = match (role, round) {
            ("implementer", 1) => (format!("impl-{issue}"), format!("{issue}-impl")),
            ("implementer", _) => (
                format!("impl-{issue}-r{round}"),
                format!("{issue}-impl{round}"),
            ),
            _ => (
                format!("rev-{issue}-r{round}"),
                format!("{issue}-rev{round}"),
            ),
        };
        Ok(Self { agent, workspace })
    }
}

fn refusal(code: &'static str, message: impl Into<String>) -> ProcessFailure {
    ProcessFailure {
        code,
        message: message.into(),
        detail: String::new(),
    }
}

fn collision(name: &str, row: &Val) -> ProcessFailure {
    refusal(
        CODE_NAME_COLLISION,
        format!(
            "Herdr name/checkout {name:?} is held by a different lane; refusing without rename, suffix or adoption: {}",
            String::from_utf8_lossy(&crate::canonical::canonical_bytes(row)).trim()
        ),
    )
}

fn git_path(
    worktree: &Path,
    flag: &str,
    timeout: Duration,
    env: &BTreeMap<String, String>,
) -> Result<PathBuf, ProcessFailure> {
    let args = [
        "rev-parse".to_string(),
        "--path-format=absolute".to_string(),
        flag.to_string(),
    ];
    match run_typed("git", &args, timeout, env, Some(worktree)) {
        ProcessOutcome::Ok(text) if !text.trim().is_empty() => Ok(PathBuf::from(text.trim())),
        ProcessOutcome::Failed(err) => Err(err),
        _ => Err(refusal(
            CODE_INCOMPLETE_IDENTITY,
            "git did not resolve the lane worktree identity",
        )),
    }
}

fn verify_workspace(row: &Val, root: &Path, checkout: &Path) -> Result<(), ProcessFailure> {
    let identity = row.get("worktree").cloned().unwrap_or_else(null);
    if !same_worktree(&herdr_str(&identity, "repo_root"), root)
        || !same_worktree(&herdr_str(&identity, "checkout_path"), checkout)
        || identity.get("is_linked_worktree").and_then(Val::as_bool) != Some(true)
        || herdr_str(&identity, "repo_name").is_empty()
    {
        return Err(refusal(
            CODE_INCOMPLETE_IDENTITY,
            format!(
                "Herdr workspace must carry its linked worktree identity: {}",
                String::from_utf8_lossy(&crate::canonical::canonical_bytes(row)).trim()
            ),
        ));
    }
    Ok(())
}

fn workspace_id(row: &Val) -> Result<String, ProcessFailure> {
    let id = herdr_str(row, "workspace_id");
    if id.is_empty() {
        return Err(refusal(
            CODE_MALFORMED,
            "workspace read-back has no workspace_id",
        ));
    }
    Ok(id)
}

fn panes(
    id: &str,
    timeout: Duration,
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<Vec<Val>, ProcessFailure> {
    let doc = herdr_call(&herdr_pane_list_args(id), timeout, env, Some(cwd))?;
    Ok(herdr_items(&doc, "panes").to_vec())
}

fn verify_pane(row: &Val, session: &SessionHandle, cwd: &Path) -> Result<String, ProcessFailure> {
    let pane = herdr_pane_identity(row)?;
    // Pane rows have no agent name; verify the same token/generation/cwd tuple.
    let mut row = row.clone();
    if let Val::Obj(fields) = &mut row {
        fields.insert("name".to_string(), string("pane-owner"));
    }
    verify_lane_binding(&row, session, Some(cwd))?;
    Ok(pane)
}

fn close_workspace(
    id: &str,
    timeout: Duration,
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<(), ProcessFailure> {
    herdr_call_effect(
        &["workspace".to_string(), "close".to_string(), id.to_string()],
        timeout,
        env,
        Some(cwd),
    )?;
    let list = herdr_call(&herdr_workspace_list_args(), timeout, env, Some(cwd))?;
    if herdr_items(&list, "workspaces")
        .iter()
        .any(|row| herdr_str(row, "workspace_id") == id)
    {
        return Err(refusal(
            CODE_MALFORMED,
            format!("workspace {id} still exists after close"),
        ));
    }
    Ok(())
}

/// Resolve by INTERNAL ownership, then read the public name back. No caller
/// addresses the hash as an agent name, and duplicate ownership fails closed.
pub(super) fn agent_name(
    session: &SessionHandle,
    timeout: Duration,
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
) -> Result<String, ProcessFailure> {
    let list = herdr_call(&herdr_agent_list_args(), timeout, env, cwd)?;
    let owned: Vec<_> = herdr_items(&list, "agents")
        .iter()
        .filter(|row| herdr_token(row, HERDR_TOKEN_LANE).as_deref() == Some(&session.session_id))
        .collect();
    if owned.len() != 1 {
        return Err(refusal(
            CODE_STALE_GENERATION,
            format!(
                "lane {:?} must resolve exactly one registered agent, found {}",
                session.session_id,
                owned.len()
            ),
        ));
    }
    Ok(verify_lane_binding(owned[0], session, cwd)?.agent)
}

/// Register or reuse a worktree-backed workspace, never an anonymous cwd.
pub(super) fn start_with_env(
    profile: &Profile,
    request: &OpRequest<'_>,
    worktree: &Path,
    env: &BTreeMap<String, String>,
) -> Result<(LaneBinding, Val, bool), ProcessFailure> {
    let names = profile.lane_names.as_ref().ok_or_else(|| {
        refusal(
            CODE_BAD_REQUEST,
            "pane start requires reviewed issue/role/round names",
        )
    })?;
    let timeout = request.timeout;
    let session = request.session;
    let role_args = herdr_role_args(profile).map_err(|err| refusal(err.code, err.message))?;
    let kind = herdr_agent_kind(profile.kind).ok_or_else(|| {
        refusal(
            CODE_EXECUTION_UNSUPPORTED,
            "no Herdr pane row for this harness",
        )
    })?;
    // Probe the substrate before touching Git: unavailable Herdr stays typed.
    let agents = herdr_call(&herdr_agent_list_args(), timeout, env, Some(worktree))?;
    for row in herdr_items(&agents, "agents") {
        if herdr_str(row, "name") == names.agent
            && herdr_token(row, HERDR_TOKEN_LANE).as_deref() != Some(&session.session_id)
        {
            return Err(collision(&names.agent, row));
        }
    }
    let git_dir = git_path(worktree, "--git-dir", timeout, env)?;
    let common = git_path(worktree, "--git-common-dir", timeout, env)?;
    let root = common
        .parent()
        .filter(|_| common.file_name().is_some_and(|name| name == ".git"))
        .ok_or_else(|| {
            refusal(
                CODE_INCOMPLETE_IDENTITY,
                "lane must belong to a non-bare repository",
            )
        })?;
    if same_worktree(&git_dir.to_string_lossy(), &common) {
        return Err(refusal(
            CODE_INCOMPLETE_IDENTITY,
            "lane checkout is not a linked Git worktree",
        ));
    }
    // Serialize retries across processes without a persistent lock owner or
    // stale-lock deletion. The lock lives in Git metadata, not tracked files.
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(git_dir.join("canter-pane.lock"))
        .map_err(|err| refusal(CODE_BAD_REQUEST, format!("lane lock: {err}")))?;
    lock.try_lock().map_err(|err| {
        refusal(
            CODE_BAD_REQUEST,
            format!("lane start already in flight: {err}"),
        )
    })?;
    let list = herdr_call(&herdr_workspace_list_args(), timeout, env, Some(worktree))?;
    let candidates: Vec<_> = herdr_items(&list, "workspaces")
        .iter()
        .filter(|row| {
            herdr_str(row, "label") == names.workspace
                || row.get("worktree").is_some_and(|identity| {
                    same_worktree(&herdr_str(identity, "checkout_path"), worktree)
                })
        })
        .collect();
    if candidates.len() > 1 {
        return Err(collision(&names.workspace, &list));
    }
    let (workspace, pane, created) = if let Some(row) = candidates.first() {
        let id = workspace_id(row)?;
        let rows = panes(&id, timeout, env, worktree)?;
        if rows.len() != 1
            || herdr_token(&rows[0], HERDR_TOKEN_LANE).as_deref() != Some(&session.session_id)
        {
            return Err(collision(&names.workspace, row));
        }
        let pane = verify_pane(&rows[0], session, worktree)?;
        verify_workspace(row, root, worktree)?;
        ((*row).clone(), pane, false)
    } else {
        let args = vec![
            "worktree".to_string(),
            "open".to_string(),
            "--cwd".to_string(),
            root.to_string_lossy().into_owned(),
            "--path".to_string(),
            worktree.to_string_lossy().into_owned(),
            "--label".to_string(),
            names.workspace.clone(),
            "--no-focus".to_string(),
        ];
        let opened = herdr_call(&args, timeout, env, Some(worktree))?;
        let workspace = opened.get("workspace").cloned().unwrap_or_else(null);
        let id = workspace_id(&workspace)?;
        // An external creator won the race. Never adopt or close its workspace.
        if opened.get("already_open").and_then(Val::as_bool) != Some(false) {
            return Err(collision(&names.workspace, &workspace));
        }
        let prepare = (|| {
            verify_workspace(&workspace, root, worktree)?;
            let rows = panes(&id, timeout, env, worktree)?;
            if rows.len() != 1 {
                return Err(refusal(
                    CODE_MALFORMED,
                    "new lane workspace must have exactly one pane",
                ));
            }
            let pane = herdr_pane_identity(&rows[0])?;
            if !same_worktree(&herdr_str(&rows[0], "cwd"), worktree) {
                return Err(refusal(
                    CODE_STALE_GENERATION,
                    "new pane has wrong checkout",
                ));
            }
            herdr_call_effect(
                &herdr_pane_report_metadata_args(
                    &pane,
                    &session.session_id,
                    session.identity.generation,
                ),
                timeout,
                env,
                Some(worktree),
            )?;
            Ok(pane)
        })();
        match prepare {
            Ok(pane) => (workspace, pane, true),
            Err(mut err) => {
                if let Err(cleanup) = close_workspace(&id, timeout, env, worktree) {
                    err.message
                        .push_str(&format!("; rollback failed for {id}: {}", cleanup.message));
                }
                return Err(err);
            }
        }
    };
    let id = workspace_id(&workspace)?;
    let launch = (|| {
        let agents = herdr_call(&herdr_agent_list_args(), timeout, env, Some(worktree))?;
        let owned: Vec<_> = herdr_items(&agents, "agents")
            .iter()
            .filter(|row| {
                herdr_token(row, HERDR_TOKEN_LANE).as_deref() == Some(&session.session_id)
            })
            .collect();
        if owned.len() > 1 {
            return Err(refusal(
                CODE_STALE_GENERATION,
                "multiple agents claim this lane",
            ));
        }
        let (agent, reused) = if let Some(row) = owned.first() {
            let binding = verify_lane_binding(row, session, Some(worktree))?;
            if binding.pane != pane {
                return Err(refusal(
                    CODE_STALE_GENERATION,
                    "lane agent is in a different pane",
                ));
            }
            (binding.agent, true)
        } else {
            if let Some(row) = herdr_items(&agents, "agents")
                .iter()
                .find(|row| herdr_str(row, "name") == names.agent)
            {
                return Err(collision(&names.agent, row));
            }
            if let Err(mut err) = herdr_call_effect(
                &herdr_agent_start_args(&names.agent, kind, &pane, &role_args),
                timeout,
                env,
                Some(worktree),
            ) {
                if err.detail.contains("agent_name_taken") {
                    err.code = CODE_NAME_COLLISION;
                }
                return Err(err);
            }
            (names.agent.clone(), false)
        };
        let row = herdr_agent_get_row(&agent, timeout, env, Some(worktree))?;
        let binding = verify_lane_binding(&row, session, Some(worktree))?;
        if binding.agent != agent || binding.pane != pane {
            return Err(refusal(
                CODE_STALE_GENERATION,
                "agent read-back changed after start",
            ));
        }
        Ok((binding, workspace.clone(), reused))
    })();
    if let Err(mut err) = launch {
        if created {
            // Only the workspace returned by OUR create is eligible for rollback.
            // Re-check its tokens first: a newer generation must never be closed.
            let owned = panes(&id, timeout, env, worktree).and_then(|rows| {
                if rows.len() == 1 {
                    verify_pane(&rows[0], session, worktree).map(|_| ())
                } else {
                    Err(refusal(
                        CODE_STALE_GENERATION,
                        "workspace ownership changed during start",
                    ))
                }
            });
            if let Err(cleanup) = owned.and_then(|()| close_workspace(&id, timeout, env, worktree))
            {
                err.message.push_str(&format!(
                    "; rollback refused/failed for {id}: {}",
                    cleanup.message
                ));
            }
        }
        return Err(err);
    }
    launch
}

/// Close only this lane generation's sole pane/workspace after p8's clean and
/// merged checks. Unowned, multi-pane and active workspaces are never closed.
pub fn close_lane_workspace(
    session: &SessionHandle,
    worktree: &Path,
    env: &BTreeMap<String, String>,
    timeout: Duration,
) -> Result<(), AdapterError> {
    let result = (|| {
        let list = herdr_call(&herdr_workspace_list_args(), timeout, env, Some(worktree))?;
        for workspace in herdr_items(&list, "workspaces") {
            if !workspace.get("worktree").is_some_and(|identity| {
                same_worktree(&herdr_str(identity, "checkout_path"), worktree)
            }) {
                continue;
            }
            let id = workspace_id(workspace)?;
            let rows = panes(&id, timeout, env, worktree)?;
            if rows.len() != 1 {
                return Err(collision(&id, workspace));
            }
            verify_pane(&rows[0], session, worktree)?;
            let agents = herdr_call(&herdr_agent_list_args(), timeout, env, Some(worktree))?;
            for row in herdr_items(&agents, "agents")
                .iter()
                .filter(|row| herdr_str(row, "pane_id") == herdr_str(&rows[0], "pane_id"))
            {
                let binding = verify_lane_binding(row, session, Some(worktree))?;
                if !matches!(binding.state.as_str(), "idle" | "done") {
                    return Err(refusal(
                        CODE_STALE_GENERATION,
                        format!(
                            "lane {} is still {}; preserve its workspace",
                            binding.agent, binding.state
                        ),
                    ));
                }
            }
            close_workspace(&id, timeout, env, worktree)?;
        }
        Ok(())
    })();
    result.map_err(|err: ProcessFailure| AdapterError::refusal(err.code, err.message))
}
