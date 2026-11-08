//! The differential tests (tests/rust in the repository: torrc, setup and the
//! guard monitors, each compared against the 2.x behaviour), run against THIS
//! build of the binary.
//!
//! Opt-in: they run only when HIDDENFORGE_DIFF_REPO names the repository root,
//! because they need Python, the 2.x reference sources and the test helpers
//! that live outside this crate. Mutation testing sets it, so every mutant is
//! graded by these tests as well as by the unit tests:
//!
//!     HIDDENFORGE_DIFF_REPO=/path/to/hiddenforge cargo mutants
//!
//! Without the variable this test passes without doing anything, which keeps
//! `cargo test` in a plain checkout self-contained.

use std::process::Command;

#[test]
fn differential_tests_against_this_build() {
    let Ok(repo) = std::env::var("HIDDENFORGE_DIFF_REPO") else {
        return;
    };
    let python = std::env::var("HIDDENFORGE_DIFF_PYTHON")
        .unwrap_or_else(|_| format!("{repo}/.venv/bin/python"));
    // A private working directory per run: pytest and hypothesis write caches
    // into the working directory, and concurrent mutants must not share one or
    // write into the repository.
    let work = std::env::temp_dir().join(format!("hf-diff-{}", std::process::id()));
    std::fs::create_dir_all(&work).expect("create a working directory");
    let status = Command::new(&python)
        .args(["-m", "pytest", "-q", "-x", "-p", "no:cacheprovider"])
        .arg(format!("{repo}/tests/rust"))
        .env("HIDDENFORGE_RUST_BIN", env!("CARGO_BIN_EXE_hiddenforge"))
        .env("HYPOTHESIS_STORAGE_DIRECTORY", work.join("hypothesis"))
        .current_dir(&work)
        .status()
        .expect("run pytest");
    let _ = std::fs::remove_dir_all(&work);
    assert!(
        status.success(),
        "the differential tests failed against this build"
    );
}
