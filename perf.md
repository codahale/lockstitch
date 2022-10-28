# Performance

```text
hash/16B                time:   [270.83 ns 270.94 ns 271.06 ns]
                        thrpt:  [56.293 MiB/s 56.318 MiB/s 56.340 MiB/s]
hash/256B               time:   [477.28 ns 477.45 ns 477.63 ns]
                        thrpt:  [511.15 MiB/s 511.34 MiB/s 511.52 MiB/s]
hash/1KiB               time:   [1.2009 µs 1.2013 µs 1.2018 µs]
                        thrpt:  [812.55 MiB/s 812.90 MiB/s 813.22 MiB/s]
hash/16KiB              time:   [2.9412 µs 2.9443 µs 2.9472 µs]
                        thrpt:  [5.1775 GiB/s 5.1826 GiB/s 5.1879 GiB/s]
hash/1MiB               time:   [160.50 µs 160.78 µs 161.06 µs]
                        thrpt:  [6.0634 GiB/s 6.0738 GiB/s 6.0844 GiB/s]

prf/16B                 time:   [268.47 ns 268.61 ns 268.77 ns]
                        thrpt:  [56.772 MiB/s 56.806 MiB/s 56.836 MiB/s]
prf/256B                time:   [265.00 ns 265.10 ns 265.21 ns]
                        thrpt:  [920.55 MiB/s 920.93 MiB/s 921.28 MiB/s]
prf/1KiB                time:   [417.78 ns 417.95 ns 418.14 ns]
                        thrpt:  [2.2808 GiB/s 2.2818 GiB/s 2.2827 GiB/s]
prf/16KiB               time:   [3.4086 µs 3.4092 µs 3.4102 µs]
                        thrpt:  [4.4745 GiB/s 4.4757 GiB/s 4.4766 GiB/s]
prf/1MiB                time:   [218.48 µs 218.74 µs 219.03 µs]
                        thrpt:  [4.4586 GiB/s 4.4644 GiB/s 4.4698 GiB/s]

stream/16B              time:   [289.48 ns 289.61 ns 289.75 ns]
                        thrpt:  [52.661 MiB/s 52.687 MiB/s 52.711 MiB/s]
stream/256B             time:   [493.77 ns 494.02 ns 494.30 ns]
                        thrpt:  [493.92 MiB/s 494.19 MiB/s 494.44 MiB/s]
stream/1KiB             time:   [1.2976 µs 1.2979 µs 1.2981 µs]
                        thrpt:  [752.28 MiB/s 752.45 MiB/s 752.58 MiB/s]
stream/16KiB            time:   [6.2039 µs 6.2087 µs 6.2139 µs]
                        thrpt:  [2.4556 GiB/s 2.4577 GiB/s 2.4595 GiB/s]
stream/1MiB             time:   [377.45 µs 377.83 µs 378.17 µs]
                        thrpt:  [2.5823 GiB/s 2.5847 GiB/s 2.5872 GiB/s]

aead/16B                time:   [543.14 ns 543.43 ns 543.83 ns]
                        thrpt:  [28.058 MiB/s 28.079 MiB/s 28.094 MiB/s]
aead/256B               time:   [742.44 ns 742.67 ns 742.91 ns]
                        thrpt:  [328.63 MiB/s 328.73 MiB/s 328.83 MiB/s]
aead/1KiB               time:   [1.6100 µs 1.6107 µs 1.6114 µs]
                        thrpt:  [606.02 MiB/s 606.29 MiB/s 606.55 MiB/s]
aead/16KiB              time:   [6.4986 µs 6.5072 µs 6.5155 µs]
                        thrpt:  [2.3419 GiB/s 2.3449 GiB/s 2.3480 GiB/s]
aead/1MiB               time:   [376.61 µs 377.29 µs 378.01 µs]
                        thrpt:  [2.5834 GiB/s 2.5884 GiB/s 2.5931 GiB/s]
```

(Benchmarks run on a GCE `n2-standard-4` with an Intel Ice Lake CPU.)
