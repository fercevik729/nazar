extern crate anyhow;

use anyhow::Result;
use std::fs;

// Utility functions for integration tests

pub fn post_test_cleanup(path: &str) -> Result<()> {
    // Utility function for cleaning up after integration tests
    // For now it only removes the logs directory after testing
    // And returns a Result
    fs::remove_dir_all(path)?;

    Ok(())
}
