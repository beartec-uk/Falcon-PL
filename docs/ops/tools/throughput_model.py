"""Round-time model for testnet 2300. Every input is labelled in THROUGHPUT.md.
T(N) = T0 + N*(k_net*bytes_ratio + k_cpu)   [median round, seconds]
Calibrated so that today's T(360) = 3.53 s (measured, 13 Oct 2026 98.1 tx/s run)."""
N_REF, T_REF = 360, 3.53          # measured
P90_OVER_MED = 5.79 / 3.53        # measured
TIMEOUT = 9.0                     # progress timeout (config)
T_MED_MAX = TIMEOUT / P90_OVER_MED / 1.2   # assumed policy: p90 keeps 20% under timeout
MIN_INTERVAL = 2.5                # config
# per-tx bytes on the critical link (KB), from the bench live-bundle fit at 60 tx (measured)
B = {"today (hex JSON)": 2.31, "PR #44 (lean body)": 1.88, "PR #44 + zstd stream": 0.83,
     "binary + zstd stream (est)": 0.74}
# body bytes per tx for the 1,000,000 B pack estimate if the constant tracks the encoding
BODY = {"today (hex JSON)": 2.23, "PR #44 (lean body)": 1.22, "PR #44 + zstd stream": 1.22,
        "binary + zstd stream (est)": 0.80}
VERIFY_MS = (0.08, 0.16)          # est: box 0.05-0.065 ms measured x1.5-2.5 assumed for Skylake
APPLY_MS = (0.3, 1.2)             # est from pack 0.13 s (v1) .. 0.56 s (v3) for 400 tx
ZSTD_MS = 0.03                    # est from bench contended half-core, per tx per link c+d
rows = []
for t0 in (1.0, 1.5, 2.0):        # est: fixed round part from the traces
    k0 = (T_REF - t0) / N_REF * 1000           # ms/tx today
    for case in ("low", "high"):
        v = VERIFY_MS[0 if case == "low" else 1]; a = APPLY_MS[0 if case == "low" else 1]
        kcpu0 = v + a
        knet0 = max(k0 - kcpu0, 0.1)
        for name, b in list(B.items()) + [("PR #44 + zstd + 2.6x verify", 0.83)]:
            ratio = b / B["today (hex JSON)"]
            vv = v / 2.6 if "2.6x" in name else v
            kcpu = vv + a + (ZSTD_MS if "zstd" in name else 0)
            k = knet0 * ratio + kcpu
            n_time = (T_MED_MAX - t0) / (k / 1000)
            body = BODY.get(name, BODY["PR #44 + zstd stream"])
            n_bytes = int((1_000_000 - 12_000) / (body * 1000))
            n = min(n_time, n_bytes)
            t = max(MIN_INTERVAL, t0 + n * k / 1000)
            tps400 = 400 / max(MIN_INTERVAL, t0 + 400 * k / 1000)
            rows.append((t0, case, name, k, n_time, n_bytes, n, n / t, tps400, 1000 / k))
print(f"T_MED_MAX={T_MED_MAX:.2f}s")
print("| T0 | case | step | ms/tx | N by time | N by 1MB | N max | tx/s at N max | tx/s at 400 | asymptote tx/s |")
print("|---|---|---|---|---|---|---|---|---|---|")
for r in rows:
    print(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]:.2f} | {r[4]:.0f} | {r[5]} | {r[6]:.0f} | {r[7]:.0f} | {r[8]:.0f} | {r[9]:.0f} |")
