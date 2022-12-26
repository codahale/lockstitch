# Performance

```text
hash/16B                time:   [217.54 ns 217.67 ns 217.82 ns]
                        thrpt:  [70.052 MiB/s 70.100 MiB/s 70.142 MiB/s]
hash/256B               time:   [429.28 ns 429.53 ns 429.83 ns]
                        thrpt:  [567.99 MiB/s 568.39 MiB/s 568.73 MiB/s]
hash/1KiB               time:   [1.1382 µs 1.1388 µs 1.1394 µs]
                        thrpt:  [857.08 MiB/s 857.56 MiB/s 857.98 MiB/s]
hash/16KiB              time:   [2.9037 µs 2.9063 µs 2.9093 µs]
                        thrpt:  [5.2449 GiB/s 5.2502 GiB/s 5.2549 GiB/s]
hash/1MiB               time:   [159.69 µs 159.92 µs 160.16 µs]
                        thrpt:  [6.0973 GiB/s 6.1067 GiB/s 6.1153 GiB/s]

prf/16B                 time:   [217.54 ns 217.67 ns 217.82 ns]
                        thrpt:  [70.051 MiB/s 70.099 MiB/s 70.142 MiB/s]
prf/256B                time:   [235.79 ns 236.01 ns 236.26 ns]
                        thrpt:  [1.0091 GiB/s 1.0102 GiB/s 1.0111 GiB/s]
prf/1KiB                time:   [292.86 ns 293.18 ns 293.54 ns]
                        thrpt:  [3.2489 GiB/s 3.2528 GiB/s 3.2564 GiB/s]
prf/16KiB               time:   [1.4369 µs 1.4378 µs 1.4389 µs]
                        thrpt:  [10.604 GiB/s 10.612 GiB/s 10.619 GiB/s]
prf/1MiB                time:   [77.779 µs 77.817 µs 77.862 µs]
                        thrpt:  [12.542 GiB/s 12.549 GiB/s 12.556 GiB/s]

stream/16B              time:   [253.99 ns 254.12 ns 254.25 ns]
                        thrpt:  [60.014 MiB/s 60.047 MiB/s 60.077 MiB/s]
stream/256B             time:   [270.11 ns 270.41 ns 270.80 ns]
                        thrpt:  [901.55 MiB/s 902.85 MiB/s 903.85 MiB/s]
stream/1KiB             time:   [335.14 ns 335.54 ns 336.07 ns]
                        thrpt:  [2.8378 GiB/s 2.8422 GiB/s 2.8456 GiB/s]
stream/16KiB            time:   [1.6211 µs 1.6225 µs 1.6241 µs]
                        thrpt:  [9.3950 GiB/s 9.4045 GiB/s 9.4124 GiB/s]
stream/1MiB             time:   [88.055 µs 88.218 µs 88.418 µs]
                        thrpt:  [11.045 GiB/s 11.070 GiB/s 11.090 GiB/s]

aead/16B                time:   [324.46 ns 324.65 ns 324.89 ns]
                        thrpt:  [46.966 MiB/s 47.001 MiB/s 47.029 MiB/s]
aead/256B               time:   [339.65 ns 339.88 ns 340.13 ns]
                        thrpt:  [717.78 MiB/s 718.31 MiB/s 718.81 MiB/s]
aead/1KiB               time:   [403.35 ns 403.70 ns 404.13 ns]
                        thrpt:  [2.3598 GiB/s 2.3623 GiB/s 2.3644 GiB/s]
aead/16KiB              time:   [1.6883 µs 1.6889 µs 1.6898 µs]
                        thrpt:  [9.0300 GiB/s 9.0345 GiB/s 9.0382 GiB/s]
aead/1MiB               time:   [88.449 µs 88.623 µs 88.814 µs]
                        thrpt:  [10.996 GiB/s 11.019 GiB/s 11.041 GiB/s]
```

(Benchmarks run on a GCE `n2-standard-4` with an Intel Ice Lake CPU with `-C
target-features=+aes,+ssse3`.)
