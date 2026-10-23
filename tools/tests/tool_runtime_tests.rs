use kernel::artifacts::registry::ArtifactRegistry;
use kernel::events::EventBus;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::Capability;
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::{tempdir, TempDir};
use tools::filesystem::{
    FilesystemToolRegistry, DEFAULT_MAX_READ_BYTES, EVENT_TOOL_EXECUTION_COMPLETED,
};
use tools::process::{ProcessToolExecutor, DEFAULT_MAX_OUTPUT_BYTES};
use tools::types::{ToolContext, ToolOutput, ToolStatus};
use uuid::Uuid;

fn runtime() -> (TempDir, EventBus, ArtifactRegistry, GrantIssuer) {
    let temp = tempdir().unwrap();
    let database_path = temp.path().join("runtime.db");
    let event_bus = EventBus::open(&database_path).unwrap();
    let registry = ArtifactRegistry::open(&database_path, temp.path().join("cas")).unwrap();
    (temp, event_bus, registry, GrantIssuer::new())
}

fn filesystem_grant(
    issuer: &GrantIssuer,
    task_id: Uuid,
    workspace: &Path,
    read: bool,
    write: bool,
) -> kernel::permissions::types::CapabilityGrant {
    let mut capabilities = Vec::new();
    if read {
        capabilities.push(Capability::FileSystemRead {
            root: workspace.canonicalize().unwrap(),
        });
    }
    if write {
        capabilities.push(Capability::FileSystemWrite {
            root: workspace.canonicalize().unwrap(),
        });
    }
    issuer.issue_grant("test_agent", task_id, capabilities, None)
}

#[test]
fn filesystem_write_is_atomic_registers_cas_and_is_audited() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let workspace = temp.path();
    let task_id = Uuid::new_v4();
    let grant = filesystem_grant(&issuer, task_id, workspace, true, true);
    let context = ToolContext::new(task_id, "test_agent");
    let artifact_id = {
        let mut filesystem = FilesystemToolRegistry::new(&event_bus, &mut registry, &issuer);
        let write_result = filesystem.write_file(
            &context,
            &grant,
            workspace,
            Path::new("nested/hello.txt"),
            b"Hello Sky OS Tools!",
        );
        assert_eq!(write_result.status, ToolStatus::Succeeded);
        let artifact = write_result
            .artifact
            .expect("successful write has CAS artifact");
        assert_eq!(artifact.size_bytes, b"Hello Sky OS Tools!".len() as u64);
        assert_eq!(
            fs::read(workspace.join("nested/hello.txt")).unwrap(),
            b"Hello Sky OS Tools!"
        );

        let read_result = filesystem.read_file(
            &context,
            &grant,
            workspace,
            Path::new("nested/hello.txt"),
            None,
        );
        assert_eq!(read_result.status, ToolStatus::Succeeded);
        assert!(matches!(
            read_result.output,
            ToolOutput::Bytes(ref bytes) if bytes == b"Hello Sky OS Tools!"
        ));
        artifact.artifact_id
    };
    assert!(registry.get_artifact(&artifact_id).unwrap().is_some());
    let events = event_bus.get_events_for_task(&task_id.to_string()).unwrap();
    assert!(events
        .iter()
        .any(|event| event.event_type == "PermissionGranted"));
    assert!(events
        .iter()
        .any(|event| event.event_type == EVENT_TOOL_EXECUTION_COMPLETED));
}

#[test]
fn filesystem_rejects_traversal_and_symlink_escape() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let workspace = temp.path().join("workspace");
    let outside = temp.path().join("outside");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"secret").unwrap();

    let task_id = Uuid::new_v4();
    let grant = filesystem_grant(&issuer, task_id, &workspace, true, true);
    let context = ToolContext::new(task_id, "test_agent");
    let filesystem = FilesystemToolRegistry::new(&event_bus, &mut registry, &issuer);
    #[cfg(windows)]
    let mut filesystem = filesystem;

    let traversal = filesystem.read_file(
        &context,
        &grant,
        &workspace,
        Path::new("../outside/secret.txt"),
        None,
    );
    assert_eq!(traversal.status, ToolStatus::Failed);

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, workspace.join("escape")).unwrap();
        let symlink_escape = filesystem.read_file(
            &context,
            &grant,
            &workspace,
            Path::new("escape/secret.txt"),
            None,
        );
        assert_eq!(symlink_escape.status, ToolStatus::Failed);

        let missing_chain_write = filesystem.write_file(
            &context,
            &grant,
            &workspace,
            Path::new("escape/newdir/created.txt"),
            b"must remain outside the workspace",
        );
        assert_eq!(missing_chain_write.status, ToolStatus::Failed);
        assert!(!outside.join("newdir").exists());

        let existing_symlink = workspace.join("existing-link.txt");
        std::os::unix::fs::symlink(outside.join("secret.txt"), &existing_symlink).unwrap();
        let symlink_escape = filesystem.read_file(
            &context,
            &grant,
            &workspace,
            Path::new("existing-link.txt"),
            None,
        );
        assert_eq!(symlink_escape.status, ToolStatus::Failed);
    }

    #[cfg(windows)]
    {
        let symlink_path = workspace.join("escape");
        match std::os::windows::fs::symlink_dir(&outside, &symlink_path) {
            Ok(()) => {
                let symlink_escape = filesystem.write_file(
                    &context,
                    &grant,
                    &workspace,
                    Path::new("escape/newdir/created.txt"),
                    b"must remain outside the workspace",
                );
                assert_eq!(symlink_escape.status, ToolStatus::Failed);
                assert!(!outside.join("newdir").exists());
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
                ) =>
            {
                eprintln!("Skipping Windows symlink assertion: {error}");
            }
            Err(error) => panic!("failed to create symlink for security test: {error}"),
        }
    }
}

#[test]
fn filesystem_rejects_oversized_reads_before_reading_contents() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let workspace = temp.path();
    let large_file = workspace.join("large.bin");
    fs::File::create(&large_file)
        .unwrap()
        .set_len(DEFAULT_MAX_READ_BYTES + 1)
        .unwrap();

    let task_id = Uuid::new_v4();
    let grant = filesystem_grant(&issuer, task_id, workspace, true, false);
    let context = ToolContext::new(task_id, "test_agent");
    let filesystem = FilesystemToolRegistry::new(&event_bus, &mut registry, &issuer);
    let result = filesystem.read_file(&context, &grant, workspace, Path::new("large.bin"), None);

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result
        .error_message
        .unwrap()
        .contains("exceeds maximum allowed limit"));
}

#[test]
fn failed_filesystem_rename_cleans_up_staged_file() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let workspace = temp.path();
    fs::create_dir(workspace.join("directory-target")).unwrap();
    let task_id = Uuid::new_v4();
    let grant = filesystem_grant(&issuer, task_id, workspace, false, true);
    let context = ToolContext::new(task_id, "test_agent");
    let mut filesystem = FilesystemToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = filesystem.write_file(
        &context,
        &grant,
        workspace,
        Path::new("directory-target"),
        b"must not replace a directory",
    );
    assert_eq!(result.status, ToolStatus::Failed);
    assert!(!fs::read_dir(workspace).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".directory-target.")
    }));
}

fn process_grant(
    issuer: &GrantIssuer,
    task_id: Uuid,
    executable: &Path,
    args_prefix: Vec<String>,
    workdir: &Path,
) -> kernel::permissions::types::CapabilityGrant {
    issuer.issue_grant(
        "test_agent",
        task_id,
        vec![Capability::ProcessExec {
            program: executable.to_string_lossy().into_owned(),
            allowed_args_prefix: args_prefix,
            allowed_workdir: workdir.canonicalize().unwrap(),
        }],
        None,
    )
}

fn process_child_args(helper: &str) -> Vec<String> {
    vec![
        "--exact".to_string(),
        helper.to_string(),
        "--nocapture".to_string(),
    ]
}

#[tokio::test]
async fn process_executor_denies_unauthorized_executable_and_persists_audit() {
    let (_temp, event_bus, _registry, issuer) = runtime();
    let workdir = std::env::current_dir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let task_id = Uuid::new_v4();
    let grant = process_grant(
        &issuer,
        task_id,
        &executable,
        process_child_args("process_child_emits_large_output"),
        &workdir,
    );
    let context = ToolContext::new(task_id, "test_agent");
    let executor = ProcessToolExecutor::new(&event_bus, &issuer);

    let result = executor
        .execute_process(
            &context,
            &grant,
            "unauthorized-program",
            &[],
            &workdir,
            None,
        )
        .await;
    assert_eq!(result.status, ToolStatus::PermissionDenied);
    let events = event_bus.get_events_for_task(&task_id.to_string()).unwrap();
    assert!(events
        .iter()
        .any(|event| event.event_type == "PermissionDenied"));
}

#[tokio::test]
async fn process_executor_bounds_stdout_and_stderr() {
    let (_temp, event_bus, _registry, issuer) = runtime();
    let workdir = std::env::current_dir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let helper_args = process_child_args("process_child_emits_large_output");
    let task_id = Uuid::new_v4();
    let grant = process_grant(&issuer, task_id, &executable, helper_args.clone(), &workdir);
    let context = ToolContext::new(task_id, "test_agent");
    let executor = ProcessToolExecutor::new(&event_bus, &issuer);

    let result = executor
        .execute_process(
            &context,
            &grant,
            &executable.to_string_lossy(),
            &helper_args,
            &workdir,
            Some(10),
        )
        .await;
    assert_eq!(result.status, ToolStatus::Succeeded);
    let ToolOutput::ProcessResult { stdout, stderr, .. } = result.output else {
        panic!("expected process output");
    };
    assert_eq!(stdout.len(), DEFAULT_MAX_OUTPUT_BYTES);
    assert_eq!(stderr.len(), DEFAULT_MAX_OUTPUT_BYTES);
    let events = event_bus.get_events_for_task(&task_id.to_string()).unwrap();
    assert!(events
        .iter()
        .any(|event| event.event_type == "PermissionGranted"));
    assert!(events
        .iter()
        .any(|event| event.event_type == "ProcessExecutionCompleted"));
}

#[tokio::test]
async fn process_executor_kills_and_reaps_timed_out_child() {
    let (_temp, event_bus, _registry, issuer) = runtime();
    let workdir = std::env::current_dir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let helper_args = process_child_args("process_child_sleeps");
    let task_id = Uuid::new_v4();
    let grant = process_grant(&issuer, task_id, &executable, helper_args.clone(), &workdir);
    let context = ToolContext::new(task_id, "test_agent");
    let executor = ProcessToolExecutor::new(&event_bus, &issuer);

    let result = executor
        .execute_process(
            &context,
            &grant,
            &executable.to_string_lossy(),
            &helper_args,
            &workdir,
            Some(1),
        )
        .await;
    assert_eq!(result.status, ToolStatus::TimedOut);
    assert!(result.error_message.unwrap().contains("killed and reaped"));
}

#[test]
fn process_child_emits_large_output() {
    if !std::env::args().any(|argument| argument == "process_child_emits_large_output") {
        return;
    }
    let output = vec![b'x'; DEFAULT_MAX_OUTPUT_BYTES + 32 * 1024];
    std::io::stdout().write_all(&output).unwrap();
    std::io::stderr().write_all(&output).unwrap();
}

#[test]
fn process_child_sleeps() {
    if std::env::args().any(|argument| argument == "process_child_sleeps") {
        std::thread::sleep(std::time::Duration::from_secs(20));
    }
}
