test blocks 100, heights [888011, 888110]; today block avg 47471 B, live gossip bundle avg 68793 B
| encoding | codec | block B/blk | block vs today | c µs/blk | d µs/blk | live bundle B/blk | bundle vs today | bundle c+d µs/blk | tx msg B | vote msg B |
|---|---|---|---|---|---|---|---|---|---|---|
| hex_json (today) | none | 47471 | +0.0% | 0 | 0 | 68793 | +0.0% | 1 | 1666 | 1461 |
| hex_json (today) | lz4 | 38682 | +18.5% | 58 | 13 | 63958 | +7.0% | 92 | 1647 | 1483 |
| hex_json (today) | snappy | 43343 | +8.7% | 37 | 14 | 66739 | +3.0% | 56 | 1648 | 1462 |
| hex_json (today) | brotli-5 | 21836 | +54.0% | 970 | 176 | 35417 | +48.5% | 1673 | 909 | 806 |
| hex_json (today) | brotli-11 | 20201 | +57.4% | 47374 | 284 | 34075 | +50.5% | 70383 | 878 | 798 |
| hex_json (today) | zstd-1 | 20991 | +55.8% | 59 | 24 | 36152 | +47.4% | 252 | 954 | 832 |
| hex_json (today) | zstd-3 | 20865 | +56.0% | 140 | 30 | 36466 | +47.0% | 368 | 960 | 840 |
| hex_json (today) | zstd-9 | 21993 | +53.7% | 668 | 51 | 36605 | +46.8% | 1201 | 961 | 842 |
| hex_json (today) | zstd-19 | 20539 | +56.7% | 6291 | 31 | 35775 | +48.0% | 5598 | 945 | 829 |
| hex_json (today) | zstd-3+dict | 19568 | +58.8% | 340 | 36 | 30666 | +55.4% | 661 | 810 | 773 |
| hex_json (today) | zstd-19+dict | 19276 | +59.4% | 5276 | 35 | 30446 | +55.7% | 7327 | 807 | 772 |
| lean_json (PR#44) | none | 33868 | +28.7% | 0 | 0 | 62877 | +8.6% | 1 | 1666 | 1461 |
| lean_json (PR#44) | lz4 | 29414 | +38.0% | 25 | 6 | 61677 | +10.3% | 79 | 1647 | 1483 |
| lean_json (PR#44) | snappy | 32108 | +32.4% | 11 | 4 | 62416 | +9.3% | 41 | 1648 | 1462 |
| lean_json (PR#44) | brotli-5 | 19955 | +58.0% | 433 | 99 | 34065 | +50.5% | 1418 | 909 | 806 |
| lean_json (PR#44) | brotli-11 | 18915 | +60.2% | 33527 | 219 | 32853 | +52.2% | 64562 | 878 | 798 |
| lean_json (PR#44) | zstd-1 | 21128 | +55.5% | 55 | 45 | 34852 | +49.3% | 254 | 954 | 832 |
| lean_json (PR#44) | zstd-3 | 20968 | +55.8% | 81 | 44 | 35244 | +48.8% | 414 | 960 | 840 |
| lean_json (PR#44) | zstd-9 | 20914 | +55.9% | 370 | 47 | 35262 | +48.7% | 1239 | 961 | 842 |
| lean_json (PR#44) | zstd-19 | 20632 | +56.5% | 4184 | 51 | 34540 | +49.8% | 4984 | 945 | 829 |
| lean_json (PR#44) | zstd-3+dict | 19372 | +59.2% | 254 | 48 | 29394 | +57.3% | 762 | 811 | 772 |
| lean_json (PR#44) | zstd-19+dict | 18377 | +61.3% | 3279 | 39 | 29547 | +57.0% | 7453 | 814 | 779 |
| lean_json_nopk | none | 32074 | +32.4% | 0 | 0 | 59289 | +13.8% | 1 | 1666 | 1461 |
| lean_json_nopk | lz4 | 27604 | +41.8% | 26 | 6 | 58178 | +15.4% | 83 | 1647 | 1483 |
| lean_json_nopk | snappy | 29313 | +38.2% | 13 | 5 | 58772 | +14.6% | 44 | 1648 | 1462 |
| lean_json_nopk | brotli-5 | 18909 | +60.2% | 457 | 119 | 32149 | +53.3% | 1479 | 909 | 806 |
| lean_json_nopk | brotli-11 | 18001 | +62.1% | 29813 | 205 | 31025 | +54.9% | 63955 | 878 | 798 |
| lean_json_nopk | zstd-1 | 19950 | +58.0% | 48 | 39 | 33002 | +52.0% | 241 | 954 | 832 |
| lean_json_nopk | zstd-3 | 19814 | +58.3% | 72 | 39 | 33336 | +51.5% | 370 | 960 | 840 |
| lean_json_nopk | zstd-9 | 19781 | +58.3% | 380 | 49 | 33337 | +51.5% | 1180 | 961 | 842 |
| lean_json_nopk | zstd-19 | 19536 | +58.8% | 3606 | 51 | 32703 | +52.5% | 4539 | 945 | 829 |
| lean_json_nopk | zstd-3+dict | 19350 | +59.2% | 216 | 41 | 29270 | +57.5% | 667 | 806 | 773 |
| lean_json_nopk | zstd-19+dict | 18365 | +61.3% | 3210 | 36 | 29504 | +57.1% | 6902 | 815 | 779 |
| binary (est) | none | 20783 | +56.2% | 0 | 0 | 31247 | +54.6% | 1 | 834 | 716 |
| binary (est) | lz4 | 19596 | +58.7% | 10 | 2 | 31119 | +54.8% | 32 | 824 | 739 |
| binary (est) | snappy | 20392 | +57.0% | 5 | 2 | 30825 | +55.2% | 26 | 809 | 721 |
| binary (est) | brotli-5 | 19223 | +59.5% | 221 | 67 | 30204 | +56.1% | 746 | 782 | 720 |
| binary (est) | brotli-11 | 18516 | +61.0% | 39439 | 87 | 30056 | +56.3% | 61084 | 778 | 720 |
| binary (est) | zstd-1 | 19067 | +59.8% | 26 | 4 | 30369 | +55.9% | 94 | 786 | 726 |
| binary (est) | zstd-3 | 18901 | +60.2% | 45 | 4 | 30352 | +55.9% | 113 | 787 | 726 |
| binary (est) | zstd-9 | 18755 | +60.5% | 191 | 5 | 30360 | +55.9% | 330 | 789 | 726 |
| binary (est) | zstd-19 | 18681 | +60.6% | 1349 | 6 | 30283 | +56.0% | 1495 | 787 | 726 |
| binary (est) | zstd-3+dict | 17898 | +62.3% | 105 | 4 | 27838 | +59.5% | 156 | 763 | 725 |
| binary (est) | zstd-19+dict | 17579 | +63.0% | 1238 | 7 | 27706 | +59.7% | 1705 | 760 | 719 |
| binary_nopk (est) | none | 19884 | +58.1% | 0 | 0 | 29449 | +57.2% | 1 | 834 | 716 |
| binary_nopk (est) | lz4 | 18621 | +60.8% | 11 | 2 | 29314 | +57.4% | 33 | 824 | 739 |
| binary_nopk (est) | snappy | 19337 | +59.3% | 6 | 3 | 29001 | +57.8% | 28 | 809 | 721 |
| binary_nopk (est) | brotli-5 | 18188 | +61.7% | 196 | 60 | 28406 | +58.7% | 757 | 782 | 720 |
| binary_nopk (est) | brotli-11 | 17607 | +62.9% | 39891 | 84 | 28257 | +58.9% | 58185 | 778 | 720 |
| binary_nopk (est) | zstd-1 | 18018 | +62.0% | 25 | 4 | 28538 | +58.5% | 95 | 786 | 726 |
| binary_nopk (est) | zstd-3 | 17943 | +62.2% | 41 | 5 | 28522 | +58.5% | 115 | 787 | 726 |
| binary_nopk (est) | zstd-9 | 17841 | +62.4% | 191 | 5 | 28533 | +58.5% | 324 | 789 | 726 |
| binary_nopk (est) | zstd-19 | 17779 | +62.5% | 1197 | 7 | 28483 | +58.6% | 1444 | 787 | 726 |
| binary_nopk (est) | zstd-3+dict | 17891 | +62.3% | 109 | 4 | 27808 | +59.6% | 156 | 762 | 724 |
| binary_nopk (est) | zstd-19+dict | 17574 | +63.0% | 1255 | 6 | 27698 | +59.7% | 1667 | 760 | 719 |

split (signatures/keys vs structure, hex body):
  sig_and_key_hex: raw 3300064 zstd3 1646282 (49.9%) brotli11 1569039 (47.5%)
  sig_and_key_raw_bytes: raw 1650032 zstd3 1598756 (96.9%) brotli11 1568494 (95.1%)
  structure_json_rest: raw 1445896 zstd3 312248 (21.6%) brotli11 273320 (18.9%)

per-link streaming zstd-3 over live bundle:
  hex_json (today) | zstd-1 stream: raw 68793 -> 22085 B/blk (+67.9% vs today raw), c 153 d 48 µs/blk
  hex_json (today) | zstd-3 stream: raw 68793 -> 22895 B/blk (+66.7% vs today raw), c 376 d 79 µs/blk
  hex_json (today) | zstd-3 stream wlog17: raw 68793 -> 23143 B/blk (+66.4% vs today raw), c 640 d 70 µs/blk
  hex_json (today) | zstd-19 stream: raw 68793 -> 21347 B/blk (+69.0% vs today raw), c 35162 d 70 µs/blk
  lean_json (PR#44) | zstd-1 stream: raw 62877 -> 20730 B/blk (+69.9% vs today raw), c 163 d 51 µs/blk
  lean_json (PR#44) | zstd-3 stream: raw 62877 -> 21560 B/blk (+68.7% vs today raw), c 353 d 80 µs/blk
  lean_json (PR#44) | zstd-3 stream wlog17: raw 62877 -> 21832 B/blk (+68.3% vs today raw), c 629 d 72 µs/blk
  lean_json (PR#44) | zstd-19 stream: raw 62877 -> 20146 B/blk (+70.7% vs today raw), c 25322 d 63 µs/blk
  lean_json_nopk | zstd-1 stream: raw 59289 -> 20181 B/blk (+70.7% vs today raw), c 144 d 45 µs/blk
  lean_json_nopk | zstd-3 stream: raw 59289 -> 21300 B/blk (+69.0% vs today raw), c 322 d 79 µs/blk
  lean_json_nopk | zstd-3 stream wlog17: raw 59289 -> 20968 B/blk (+69.5% vs today raw), c 600 d 72 µs/blk
  lean_json_nopk | zstd-19 stream: raw 59289 -> 20064 B/blk (+70.8% vs today raw), c 23826 d 67 µs/blk
  binary (est) | zstd-1 stream: raw 31247 -> 19901 B/blk (+71.1% vs today raw), c 81 d 10 µs/blk
  binary (est) | zstd-3 stream: raw 31247 -> 19399 B/blk (+71.8% vs today raw), c 120 d 11 µs/blk
  binary (est) | zstd-3 stream wlog17: raw 31247 -> 19980 B/blk (+71.0% vs today raw), c 211 d 11 µs/blk
  binary (est) | zstd-19 stream: raw 31247 -> 19344 B/blk (+71.9% vs today raw), c 3073 d 20 µs/blk
  binary_nopk (est) | zstd-1 stream: raw 29449 -> 19415 B/blk (+71.8% vs today raw), c 86 d 10 µs/blk
  binary_nopk (est) | zstd-3 stream: raw 29449 -> 19276 B/blk (+72.0% vs today raw), c 116 d 11 µs/blk
  binary_nopk (est) | zstd-3 stream wlog17: raw 29449 -> 19303 B/blk (+71.9% vs today raw), c 206 d 11 µs/blk
  binary_nopk (est) | zstd-19 stream: raw 29449 -> 19260 B/blk (+72.0% vs today raw), c 3004 d 19 µs/blk

component share of today's live bundle: {'header': '15.8%', 'body_by_id': '26.6%', 'votes': '12.7%', 'txs': '43.2%', 'tx_inv': '1.8%'}
