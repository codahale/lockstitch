# Performance

## `x86_64` (GCP `c4-standard-4`, Intel Emerald Rapids, Debian 12, rustc 1.84.1, `-target-cpu=native`)

```text
aead/16B                time:   [2.1872 µs 2.1963 µs 2.2051 µs]
                        thrpt:  [6.9197 MiB/s 6.9476 MiB/s 6.9765 MiB/s]
aead/256B               time:   [2.2016 µs 2.2101 µs 2.2189 µs]
                        thrpt:  [110.03 MiB/s 110.46 MiB/s 110.89 MiB/s]
aead/1KiB               time:   [2.2521 µs 2.2592 µs 2.2661 µs]
                        thrpt:  [430.94 MiB/s 432.27 MiB/s 433.62 MiB/s]
aead/16KiB              time:   [3.3592 µs 3.3710 µs 3.3838 µs]
                        thrpt:  [4.5094 GiB/s 4.5265 GiB/s 4.5423 GiB/s]
aead/1MiB               time:   [76.521 µs 76.770 µs 77.012 µs]
                        thrpt:  [12.681 GiB/s 12.721 GiB/s 12.762 GiB/s]

hash/16B                time:   [1.5208 µs 1.5262 µs 1.5315 µs]
                        thrpt:  [9.9632 MiB/s 9.9979 MiB/s 10.034 MiB/s]
hash/256B               time:   [1.6931 µs 1.6988 µs 1.7046 µs]
                        thrpt:  [143.23 MiB/s 143.71 MiB/s 144.20 MiB/s]
hash/1KiB               time:   [2.1721 µs 2.1783 µs 2.1848 µs]
                        thrpt:  [446.97 MiB/s 448.31 MiB/s 449.60 MiB/s]
hash/16KiB              time:   [11.949 µs 11.988 µs 12.028 µs]
                        thrpt:  [1.2686 GiB/s 1.2728 GiB/s 1.2770 GiB/s]
hash/1MiB               time:   [678.21 µs 680.12 µs 681.99 µs]
                        thrpt:  [1.4319 GiB/s 1.4359 GiB/s 1.4399 GiB/s]

prf/16B                 time:   [1.5607 µs 1.5651 µs 1.5697 µs]
                        thrpt:  [9.7209 MiB/s 9.7496 MiB/s 9.7767 MiB/s]
prf/256B                time:   [2.4703 µs 2.4784 µs 2.4871 µs]
                        thrpt:  [98.164 MiB/s 98.506 MiB/s 98.831 MiB/s]
prf/1KiB                time:   [5.6582 µs 5.6761 µs 5.6937 µs]
                        thrpt:  [171.52 MiB/s 172.05 MiB/s 172.59 MiB/s]

stream/16B              time:   [1.7780 µs 1.7838 µs 1.7900 µs]
                        thrpt:  [8.5244 MiB/s 8.5540 MiB/s 8.5821 MiB/s]
stream/256B             time:   [1.7850 µs 1.7901 µs 1.7954 µs]
                        thrpt:  [135.98 MiB/s 136.38 MiB/s 136.77 MiB/s]
stream/1KiB             time:   [1.8378 µs 1.8449 µs 1.8518 µs]
                        thrpt:  [527.37 MiB/s 529.32 MiB/s 531.37 MiB/s]
stream/16KiB            time:   [2.9536 µs 2.9627 µs 2.9715 µs]
                        thrpt:  [5.1350 GiB/s 5.1504 GiB/s 5.1662 GiB/s]
stream/1MiB             time:   [76.153 µs 76.365 µs 76.582 µs]
                        thrpt:  [12.752 GiB/s 12.788 GiB/s 12.824 GiB/s]
```

## `aarch64` (Apple MacBook Pro `Mac15,6` M3 Pro, macOS 15.3, rustc 1.84.1)

```text
aead/16B                time:   [1.0561 µs 1.0563 µs 1.0566 µs]
                        thrpt:  [14.442 MiB/s 14.445 MiB/s 14.449 MiB/s]
aead/256B               time:   [1.0704 µs 1.0843 µs 1.1040 µs]
                        thrpt:  [221.13 MiB/s 225.16 MiB/s 228.09 MiB/s]
aead/1KiB               time:   [1.1036 µs 1.1109 µs 1.1202 µs]
                        thrpt:  [871.79 MiB/s 879.07 MiB/s 884.87 MiB/s]
aead/16KiB              time:   [1.8721 µs 1.8842 µs 1.8980 µs]
                        thrpt:  [8.0393 GiB/s 8.0981 GiB/s 8.1505 GiB/s]
aead/1MiB               time:   [52.378 µs 52.579 µs 52.825 µs]
                        thrpt:  [18.487 GiB/s 18.573 GiB/s 18.645 GiB/s]

hash/16B                time:   [771.39 ns 778.14 ns 790.58 ns]
                        thrpt:  [19.301 MiB/s 19.609 MiB/s 19.781 MiB/s]
hash/256B               time:   [854.14 ns 856.01 ns 858.39 ns]
                        thrpt:  [284.42 MiB/s 285.21 MiB/s 285.83 MiB/s]
hash/1KiB               time:   [1.1449 µs 1.1529 µs 1.1622 µs]
                        thrpt:  [840.30 MiB/s 847.08 MiB/s 852.95 MiB/s]
hash/16KiB              time:   [6.8562 µs 6.8995 µs 6.9502 µs]
                        thrpt:  [2.1954 GiB/s 2.2116 GiB/s 2.2256 GiB/s]
hash/1MiB               time:   [388.18 µs 389.54 µs 391.16 µs]
                        thrpt:  [2.4966 GiB/s 2.5070 GiB/s 2.5157 GiB/s]

prf/16B                 time:   [762.27 ns 764.83 ns 768.14 ns]
                        thrpt:  [19.865 MiB/s 19.950 MiB/s 20.018 MiB/s]
prf/256B                time:   [1.2606 µs 1.2651 µs 1.2707 µs]
                        thrpt:  [192.14 MiB/s 192.98 MiB/s 193.67 MiB/s]
prf/1KiB                time:   [2.9024 µs 2.9270 µs 2.9582 µs]
                        thrpt:  [330.12 MiB/s 333.64 MiB/s 336.46 MiB/s]

stream/16B              time:   [892.54 ns 896.65 ns 901.69 ns]
                        thrpt:  [16.922 MiB/s 17.018 MiB/s 17.096 MiB/s]
stream/256B             time:   [917.38 ns 926.03 ns 934.77 ns]
                        thrpt:  [261.18 MiB/s 263.64 MiB/s 266.13 MiB/s]
stream/1KiB             time:   [922.62 ns 923.65 ns 925.50 ns]
                        thrpt:  [1.0304 GiB/s 1.0325 GiB/s 1.0337 GiB/s]
stream/16KiB            time:   [1.6735 µs 1.6752 µs 1.6777 µs]
                        thrpt:  [9.0950 GiB/s 9.1085 GiB/s 9.1180 GiB/s]
stream/1MiB             time:   [54.184 µs 54.388 µs 54.574 µs]
                        thrpt:  [17.894 GiB/s 17.956 GiB/s 18.023 GiB/s]
```
