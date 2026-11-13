//! Python bindings (enabled with `--features python`, built by maturin).

use crate::{Category, Finding, Scrubber, TokenMap};
use pyo3::prelude::*;
use std::collections::BTreeMap;

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

    /// Replace every finding with a numbered token, e.g. `[SSN_1]`.
    ///
    /// Returns `(text, token_map)`. Keep `token_map` local and pass it to
    /// `restore` to get the original text back.
    fn redact_reversible(&self, text: &str) -> (String, BTreeMap<String, String>) {
        let redaction = self.inner.redact_reversible(text);
        let token_map = redaction
            .map
            .iter()
            .map(|(token, value)| (token.to_owned(), value.to_owned()))
            .collect();
        (redaction.text, token_map)
    }
}

/// Put the original values back into `text`, using a token map from
/// `Scrubber.redact_reversible`. Tokens the map does not know are left alone.
#[pyfunction]
fn restore(text: &str, token_map: BTreeMap<String, String>) -> String {
    let map: TokenMap = token_map.into_iter().collect();
    crate::restore(text, &map)
}

/// Native extension module.
#[pymodule]
fn phi_scrub(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyScrubber>()?;
    m.add_class::<PyFinding>()?;
    m.add_function(wrap_pyfunction!(restore, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
