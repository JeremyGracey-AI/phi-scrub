//! Python bindings (enabled with `--features python`, built by maturin).

use crate::{Category, Finding, Scrubber};
use pyo3::prelude::*;

/// A single PHI detection.
#[pyclass(name = "Finding", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyFinding {
    /// Byte offset where the match starts.
    #[pyo3(get)]
    pub start: usize,
    /// Byte offset where the match ends (exclusive).
    #[pyo3(get)]
    pub end: usize,
    /// Category name: "ssn", "phone", or "email".
    #[pyo3(get)]
    pub category: String,
}

impl From<Finding> for PyFinding {
    fn from(f: Finding) -> Self {
        let category = match f.category {
            Category::Ssn => "ssn",
            Category::Phone => "phone",
            Category::Email => "email",
        }
        .to_owned();
        Self {
            start: f.start,
            end: f.end,
            category,
        }
    }
}

#[pymethods]
impl PyFinding {
    fn __repr__(&self) -> String {
        format!(
            "Finding(start={}, end={}, category={:?})",
            self.start, self.end, self.category
        )
    }
}

/// PHI/PII redaction engine.
#[pyclass(name = "Scrubber", frozen)]
pub struct PyScrubber {
    inner: Scrubber,
}

#[pymethods]
impl PyScrubber {
    #[new]
    fn new() -> Self {
        Self {
            inner: Scrubber::new(),
        }
    }

    /// Return all findings in `text`, sorted by start offset.
    fn detect(&self, text: &str) -> Vec<PyFinding> {
        self.inner
            .detect(text)
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Replace every finding with its category token, e.g. `[SSN]`.
    fn redact(&self, text: &str) -> String {
        self.inner.redact(text)
    }
}

/// Native extension module.
#[pymodule]
fn phi_scrub(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyScrubber>()?;
    m.add_class::<PyFinding>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
