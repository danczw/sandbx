use crate::SandboxError;

/// Whether the running kernel can enforce a sandbox.
///
/// A [`crate::SandboxPolicy`] is a promise; this is whether the machine can keep
/// it. Probing is separated from the decision made about it ([`detect`] versus
/// [`new`]) so the fail-closed path is testable on a machine whose own kernel is
/// perfectly capable — otherwise the one path that must never be wrong could
/// only be exercised by finding an ancient kernel, and so would never be
/// exercised at all.
///
/// Only filesystem enforcement is reported. Landlock's network rules cover TCP
/// bind/connect only, which is not how sandbx denies network access — that comes
/// from an empty network namespace, a separate capability.
///
/// [`detect`]: KernelSupport::detect
/// [`new`]: KernelSupport::new
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelSupport {
    filesystem: bool,
}

impl KernelSupport {
    /// Build a report directly, bypassing detection.
    ///
    /// Exists so tests can assert what sandbx does on a kernel the test machine is
    /// not running.
    pub fn new(filesystem: bool) -> Self {
        Self { filesystem }
    }

    /// Ask the running kernel whether Landlock is usable.
    ///
    /// Builds a ruleset and immediately drops it. Creating a ruleset allocates a
    /// kernel object but restricts nothing — only `restrict_self` applies — so
    /// this is safe to call from the parent process.
    ///
    /// Reports unsupported on non-Linux platforms.
    pub fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};

            // Must match the baseline `helper::apply` hard-requires, or this
            // reports "supported" on a kernel where applying the policy then
            // fails. HardRequirement makes it fail rather than downgrade.
            let probe = Ruleset::default()
                .set_compatibility(CompatLevel::HardRequirement)
                .handle_access(AccessFs::from_all(ABI::V5))
                .and_then(Ruleset::create);

            Self::new(probe.is_ok())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Self::new(false)
        }
    }

    /// Whether filesystem rules will actually be enforced.
    pub fn enforces_filesystem(&self) -> bool {
        self.filesystem
    }

    /// Refuse a kernel that cannot enforce a sandbox.
    ///
    /// Fail-closed: a caller that believes it is sandboxed and is not is worse
    /// off than one that gets an error, so there is deliberately no "degrade to
    /// unrestricted" path.
    pub fn require_enforceable(&self) -> Result<(), SandboxError> {
        if self.filesystem {
            Ok(())
        } else {
            Err(SandboxError::Unsupported {
                detail: if cfg!(target_os = "linux") {
                    "kernel cannot enforce the required Landlock access rights \
                     (needs Linux 6.10+ with Landlock enabled at boot)"
                } else {
                    "sandboxing is only implemented for Linux"
                },
            })
        }
    }
}
