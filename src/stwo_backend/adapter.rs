/// Official `stwo` crate version wired into the Phase 2 seam.
pub const STWO_CRATE_VERSION_PHASE2: &str = "2.2.0";
/// Official `stwo-constraint-framework` crate version wired into the Phase 2 seam.
pub const STWO_CONSTRAINT_FRAMEWORK_VERSION_PHASE2: &str = "2.2.0";

#[cfg(feature = "stwo-backend")]
type StwoPhase2BaseField = stwo::core::fields::m31::BaseField;
#[cfg(feature = "stwo-backend")]
type StwoPhase2TraceLocationAllocator = stwo_constraint_framework::TraceLocationAllocator;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StwoDependencySeam {
    pub stwo_crate: &'static str,
    pub stwo_crate_version: &'static str,
    pub constraint_framework_crate: &'static str,
    pub constraint_framework_version: &'static str,
    pub adapter_module: &'static str,
    pub layout_module: &'static str,
}

/// Returns the official dependency seam used by the Phase 2 S-two backend layout.
pub fn phase2_dependency_seam() -> StwoDependencySeam {
    #[cfg(feature = "stwo-backend")]
    compile_probe();

    StwoDependencySeam {
        stwo_crate: "stwo",
        stwo_crate_version: STWO_CRATE_VERSION_PHASE2,
        constraint_framework_crate: "stwo-constraint-framework",
        constraint_framework_version: STWO_CONSTRAINT_FRAMEWORK_VERSION_PHASE2,
        adapter_module: "src/stwo_backend/adapter.rs",
        layout_module: "src/stwo_backend/layout.rs",
    }
}

#[cfg(feature = "stwo-backend")]
fn compile_probe() {
    let _ = core::mem::size_of::<StwoPhase2BaseField>();
    let _ = core::mem::size_of::<StwoPhase2TraceLocationAllocator>();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase2_dependency_seam_reports_official_crates() {
        let seam = phase2_dependency_seam();
        assert_eq!(seam.stwo_crate, "stwo");
        assert_eq!(seam.stwo_crate_version, STWO_CRATE_VERSION_PHASE2);
        assert_eq!(seam.constraint_framework_crate, "stwo-constraint-framework");
        assert_eq!(
            seam.constraint_framework_version,
            STWO_CONSTRAINT_FRAMEWORK_VERSION_PHASE2
        );
    }
}
