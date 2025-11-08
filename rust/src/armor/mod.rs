//! Versioned armoring for binary data

use anyhow::Result;

pub fn wrap(_body: &[u8]) -> String {
    // TODO: Step 3
    todo!("wrap not yet implemented")
}

pub fn unwrap(_armored: &str) -> Result<Vec<u8>> {
    // TODO: Step 3
    todo!("unwrap not yet implemented")
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_placeholder() {
        // Placeholder test.
    }
}
