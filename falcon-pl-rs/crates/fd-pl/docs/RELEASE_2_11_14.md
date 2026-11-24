# Falcon PL 2.11.14: evict unapplicable withdraw and key-bind txs (testnet 2300)

**No activation height. No consensus change. Rolling-upgrade compatible with 2.11.13.**
Mempool policy only. The block format, signatures, 4-of-6 commit QC and the
packer lottery are unchanged.

## Why
After 2.11.13 activated, v10's pool held two transactions that can never
apply:

* dave seq 63: `duplicate withdraw note`
* falcon-node#seat seq 0: `key bind: account has no key and this key is not committed ...`

Both were classed as transient, so they were never evicted. When they were
all v10 had, it packed no block and its turn went to view change (about
173 s lost over 14 skipped turns in the activation window).

## What changed (local)
`Node::is_permanent_tx_failure` now treats `duplicate withdraw note` and
`KEY_BIND_REFUSED` as permanent failures. The packer and the applicable-head
sanitizer evict those txs from the mempool, the same way as other poison
txs (`insufficient balance`, `BTC duplicate header`, and so on).

A first-key that later becomes valid, after a `pay_to_key` commit, must be
submitted again.

## Tests
* `duplicate_withdraw_and_key_bind_refused_are_permanent`
