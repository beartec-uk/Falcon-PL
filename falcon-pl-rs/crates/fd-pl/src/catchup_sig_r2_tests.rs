// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! v2.9.66 audit R-2: catch-up verifies per-tx Falcon sigs by default.

#[test]
fn catchup_skip_tx_sig_defaults_off() {
    // OnceLock: only assert default when env unset in this process.
    if std::env::var("FPL_CATCHUP_SKIP_TX_SIG").is_err() {
        assert!(!crate::catchup_skip_tx_sig());
    }
}

#[test]
fn product_version_is_2975() {
    assert_eq!(crate::PRODUCT_VERSION, "2.11.2");
}
