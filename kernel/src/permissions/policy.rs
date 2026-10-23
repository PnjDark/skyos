pub struct PolicyValidator;

impl PolicyValidator {
    /// Validates a filesystem request against a root capability using path normalization & lexical containment checks.
    pub fn validate_fs_access(requested_path: &std::path::Path, root: &std::path::Path) -> bool {
        let normalized_requested = Self::normalize_path(requested_path);
        let normalized_root = Self::normalize_path(root);
        normalized_requested.starts_with(&normalized_root)
    }

    /// Validates a process execution request against a capability.
    /// Ensures the program matches exactly, arguments start with allowed prefixes, and workdir is within allowed workdir.
    pub fn validate_process_exec(
        program: &str,
        args: &[String],
        workdir: &std::path::Path,
        allowed_program: &str,
        allowed_args_prefix: &[String],
        allowed_workdir: &std::path::Path,
    ) -> bool {
        if program != allowed_program {
            return false;
        }
        // Check each argument matches exactly the allowed prefix sequence
        if args.len() < allowed_args_prefix.len() {
            return false;
        }
        for (arg, allowed) in args.iter().zip(allowed_args_prefix.iter()) {
            if arg != allowed {
                return false;
            }
        }
        // Workdir must be within allowed_workdir after normalization
        Self::validate_fs_access(workdir, allowed_workdir)
    }

    /// Lexically normalizes a path without requiring it to exist on disk (resolving . and .. components).
    pub fn normalize_path(path: &std::path::Path) -> std::path::PathBuf {
        use std::path::Component;
        let mut components: Vec<std::ffi::OsString> = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => {
                    components.clear();
                    components.push(component.as_os_str().to_owned());
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    components.pop();
                }
                Component::Normal(c) => {
                    components.push(c.to_owned());
                }
            }
        }
        components.iter().collect()
    }
}
