# Deploy seat_sync.py to the co-signer seats (falcon2, beartec-brain)

**Not deployed.** Run this only with Scott's OK, at a quiet time, and one seat at a time.

## What changes
- **Seats today:** falcon2 and beartec-brain both run `/opt/fpl-operator/bin/seat_sync.py` with sha256 `139e9529d2fb648dcc5bfbf60ca8662983f9964f510fad000e96dac53e496d4b` (read-only check, 15 Nov 2026 04:00 GMT). That is the version from before #41: it has no `reap`, so a participant keeps running after the lead drops its request.
- **New `seat_sync.py`:**
  - stops the participant when the lead stops listing the request, including a participant left running by an earlier seat_sync process (found via /proc);
  - never starts a second participant for a request where this seat already announced a key;
  - an error on one request no longer blocks the other requests.
- **New unit:** `fpl-bridge-seat-sync.service` gets `KillMode=process`, so a seat_sync restart no longer kills in-flight participants.

## Preconditions (check on the lead, falcon1, read-only)
1. No ceremony is in flight. On falcon1, `curl -s http://<lead tailnet ip>:8791/seat/requests` should return `[]`. If it doesn't, check `fpl_bridge_intake.py --plan` and wait.
2. The loadgen is paused and no peg-in is being opened.
3. On the seat, no participant is running: `pgrep -a fpl_ceremony_par` shows nothing. Use `pgrep -a`, not `pgrep -fc`, because `-f` also matches the ssh command line.

## Steps, per seat (falcon2 first, then beartec-brain)
1. Back up:
   ```
   install -d /opt/fpl-operator/backup-$(date -u +%Y%m%dT%H%M)
   cp -a /opt/fpl-operator/bin/seat_sync.py /etc/systemd/system/fpl-bridge-seat-sync.service /opt/fpl-operator/backup-*/
   ```
2. Copy `seat_sync.py` from the merged commit to `/opt/fpl-operator/bin/seat_sync.py.new`, check its sha256 against the merged file, then `chmod 0755` it and `mv` it into place.
3. Unit: either add `KillMode=process` under `[Service]` in `/etc/systemd/system/fpl-bridge-seat-sync.service`, or install the repo unit file (keep the local `EnvironmentFile`). Then run `systemctl daemon-reload`.
4. `systemctl restart fpl-bridge-seat-sync`. Restart **only** this unit. Don't touch fpl-operatord, the node, or Tailscale.
5. Verify:
   - `systemctl is-active fpl-bridge-seat-sync` shows active;
   - `journalctl -u fpl-bridge-seat-sync -n 20` shows no `sync error` loop;
   - `systemctl show -p KillMode fpl-bridge-seat-sync` shows `KillMode=process`.
6. Next ceremony: each seat logs `started participant for <id>`, and after the request completes or fails it logs `stopped participant for <id>`.

## Rollback
Copy the backup files back, run `systemctl daemon-reload`, and restart `fpl-bridge-seat-sync`.
