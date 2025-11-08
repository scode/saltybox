# Validation of changes (always run when done making changes)

Perform validation in this order

* `cargo check`
* `cargo clippy --all-targets --all-features -- -D warnings`
* `cargo fmt`
* `cargo test` (slow, especially important not to constantly run this, hence it is last)

Don't consider yourself done until you have fixed all issues reported.

