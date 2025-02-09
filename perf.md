# Performance

## `x86_64` (GCP `c4-standard-4`, Intel Emerald Rapids, Debian 12, rustc 1.84.1, `-target-cpu=native`)

```text
aead/16B                time:   [1.7621 µs 1.7671 µs 1.7723 µs]
                        thrpt:  [8.6097 MiB/s 8.6348 MiB/s 8.6597 MiB/s]
aead/256B               time:   [1.7804 µs 1.7854 µs 1.7906 µs]
                        thrpt:  [136.35 MiB/s 136.74 MiB/s 137.13 MiB/s]
aead/1KiB               time:   [1.8346 µs 1.8402 µs 1.8459 µs]
                        thrpt:  [529.04 MiB/s 530.68 MiB/s 532.31 MiB/s]
aead/16KiB              time:   [2.9379 µs 2.9494 µs 2.9606 µs]
                        thrpt:  [5.1539 GiB/s 5.1735 GiB/s 5.1939 GiB/s]
aead/1MiB               time:   [75.641 µs 75.978 µs 76.331 µs]
                        thrpt:  [12.794 GiB/s 12.853 GiB/s 12.911 GiB/s]

hash/16B                time:   [957.71 ns 960.83 ns 963.86 ns]
                        thrpt:  [15.831 MiB/s 15.881 MiB/s 15.933 MiB/s]
hash/256B               time:   [1.1341 µs 1.1371 µs 1.1401 µs]
                        thrpt:  [214.14 MiB/s 214.71 MiB/s 215.27 MiB/s]
hash/1KiB               time:   [1.6136 µs 1.6176 µs 1.6216 µs]
                        thrpt:  [602.21 MiB/s 603.71 MiB/s 605.21 MiB/s]
hash/16KiB              time:   [11.384 µs 11.413 µs 11.443 µs]
                        thrpt:  [1.3335 GiB/s 1.3370 GiB/s 1.3404 GiB/s]
hash/1MiB               time:   [667.84 µs 669.63 µs 671.29 µs]
                        thrpt:  [1.4548 GiB/s 1.4584 GiB/s 1.4623 GiB/s]

prf/16B                 time:   [944.32 ns 946.59 ns 948.92 ns]
                        thrpt:  [16.080 MiB/s 16.120 MiB/s 16.159 MiB/s]
prf/256B                time:   [950.86 ns 953.16 ns 955.60 ns]
                        thrpt:  [255.48 MiB/s 256.14 MiB/s 256.76 MiB/s]
prf/1KiB                time:   [1.0223 µs 1.0253 µs 1.0285 µs]
                        thrpt:  [949.49 MiB/s 952.50 MiB/s 955.28 MiB/s]
prf/16KiB               time:   [2.4993 µs 2.5072 µs 2.5151 µs]
                        thrpt:  [6.0669 GiB/s 6.0860 GiB/s 6.1051 GiB/s]
prf/1MiB                time:   [107.74 µs 108.07 µs 108.39 µs]
                        thrpt:  [9.0101 GiB/s 9.0367 GiB/s 9.0638 GiB/s]

stream/16B              time:   [1.4048 µs 1.4095 µs 1.4140 µs]
                        thrpt:  [10.791 MiB/s 10.826 MiB/s 10.862 MiB/s]
stream/256B             time:   [1.4166 µs 1.4202 µs 1.4239 µs]
                        thrpt:  [171.46 MiB/s 171.91 MiB/s 172.35 MiB/s]
stream/1KiB             time:   [1.4682 µs 1.4739 µs 1.4798 µs]
                        thrpt:  [659.94 MiB/s 662.59 MiB/s 665.13 MiB/s]
stream/16KiB            time:   [2.5477 µs 2.5574 µs 2.5668 µs]
                        thrpt:  [5.9446 GiB/s 5.9666 GiB/s 5.9893 GiB/s]
stream/1MiB             time:   [74.556 µs 74.869 µs 75.202 µs]
                        thrpt:  [12.986 GiB/s 13.044 GiB/s 13.098 GiB/s]
```

## `aarch64` (Apple MacBook Pro `Mac15,6` M3 Pro, macOS 15.3, rustc 1.84.1)

```text
aead/16B                time:   [913.27 ns 913.86 ns 914.69 ns]
                        thrpt:  [16.682 MiB/s 16.697 MiB/s 16.708 MiB/s]
aead/256B               time:   [931.71 ns 931.93 ns 932.20 ns]
                        thrpt:  [261.90 MiB/s 261.97 MiB/s 262.03 MiB/s]
aead/1KiB               time:   [969.60 ns 970.29 ns 971.02 ns]
                        thrpt:  [1005.7 MiB/s 1006.5 MiB/s 1007.2 MiB/s]
aead/16KiB              time:   [1.7194 µs 1.7203 µs 1.7214 µs]
                        thrpt:  [8.8641 GiB/s 8.8697 GiB/s 8.8745 GiB/s]
aead/1MiB               time:   [52.044 µs 52.075 µs 52.127 µs]
                        thrpt:  [18.734 GiB/s 18.753 GiB/s 18.764 GiB/s]

hash/16B                time:   [466.77 ns 466.91 ns 467.08 ns]
                        thrpt:  [32.669 MiB/s 32.680 MiB/s 32.690 MiB/s]
hash/256B               time:   [563.15 ns 567.98 ns 578.26 ns]
                        thrpt:  [422.20 MiB/s 429.84 MiB/s 433.53 MiB/s]
hash/1KiB               time:   [842.05 ns 842.43 ns 842.96 ns]
                        thrpt:  [1.1313 GiB/s 1.1320 GiB/s 1.1326 GiB/s]
hash/16KiB              time:   [6.5031 µs 6.5058 µs 6.5103 µs]
                        thrpt:  [2.3438 GiB/s 2.3454 GiB/s 2.3464 GiB/s]
hash/1MiB               time:   [387.33 µs 387.86 µs 388.49 µs]
                        thrpt:  [2.5137 GiB/s 2.5178 GiB/s 2.5213 GiB/s]

prf/16B                 time:   [466.90 ns 471.45 ns 479.64 ns]
                        thrpt:  [31.813 MiB/s 32.365 MiB/s 32.681 MiB/s]
prf/256B                time:   [486.28 ns 487.99 ns 490.48 ns]
                        thrpt:  [497.76 MiB/s 500.30 MiB/s 502.06 MiB/s]
prf/1KiB                time:   [528.30 ns 528.50 ns 528.74 ns]
                        thrpt:  [1.8037 GiB/s 1.8045 GiB/s 1.8052 GiB/s]
prf/16KiB               time:   [1.4058 µs 1.4065 µs 1.4074 µs]
                        thrpt:  [10.842 GiB/s 10.849 GiB/s 10.855 GiB/s]
prf/1MiB                time:   [55.831 µs 55.863 µs 55.910 µs]
                        thrpt:  [17.467 GiB/s 17.481 GiB/s 17.491 GiB/s]

stream/16B              time:   [736.19 ns 736.49 ns 736.91 ns]
                        thrpt:  [20.706 MiB/s 20.718 MiB/s 20.727 MiB/s]
stream/256B             time:   [752.82 ns 757.27 ns 765.10 ns]
                        thrpt:  [319.10 MiB/s 322.40 MiB/s 324.30 MiB/s]
stream/1KiB             time:   [786.70 ns 787.52 ns 788.63 ns]
                        thrpt:  [1.2093 GiB/s 1.2110 GiB/s 1.2123 GiB/s]
stream/16KiB            time:   [1.5374 µs 1.5381 µs 1.5393 µs]
                        thrpt:  [9.9126 GiB/s 9.9204 GiB/s 9.9249 GiB/s]
stream/1MiB             time:   [51.904 µs 51.935 µs 51.972 µs]
                        thrpt:  [18.790 GiB/s 18.804 GiB/s 18.815 GiB/s]
```
