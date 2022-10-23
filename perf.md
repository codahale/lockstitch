# Performance

```text
hash/16B                time:   [248.05 ns 248.18 ns 248.32 ns]                     
                        thrpt:  [61.448 MiB/s 61.484 MiB/s 61.515 MiB/s]
hash/256B               time:   [461.95 ns 462.18 ns 462.43 ns]                      
                        thrpt:  [527.95 MiB/s 528.24 MiB/s 528.50 MiB/s]
hash/1KiB               time:   [1.1706 µs 1.1712 µs 1.1718 µs]                       
                        thrpt:  [833.41 MiB/s 833.84 MiB/s 834.26 MiB/s]
hash/16KiB              time:   [2.9496 µs 2.9526 µs 2.9560 µs]                        
                        thrpt:  [5.1619 GiB/s 5.1679 GiB/s 5.1732 GiB/s]
hash/1MiB               time:   [160.81 µs 160.98 µs 161.16 µs]                      
                        thrpt:  [6.0595 GiB/s 6.0664 GiB/s 6.0726 GiB/s]

prf/16B                 time:   [248.67 ns 248.80 ns 248.96 ns]                    
                        thrpt:  [61.289 MiB/s 61.328 MiB/s 61.363 MiB/s]
prf/256B                time:   [262.26 ns 262.39 ns 262.51 ns]                     
                        thrpt:  [930.03 MiB/s 930.47 MiB/s 930.91 MiB/s]
prf/1KiB                time:   [425.82 ns 426.09 ns 426.45 ns]                     
                        thrpt:  [2.2363 GiB/s 2.2382 GiB/s 2.2396 GiB/s]
prf/16KiB               time:   [3.7333 µs 3.7354 µs 3.7378 µs]                       
                        thrpt:  [4.0823 GiB/s 4.0849 GiB/s 4.0872 GiB/s]
prf/1MiB                time:   [226.08 µs 226.30 µs 226.54 µs]                     
                        thrpt:  [4.3108 GiB/s 4.3154 GiB/s 4.3195 GiB/s]

stream/16B              time:   [291.61 ns 291.81 ns 292.01 ns]                       
                        thrpt:  [52.254 MiB/s 52.291 MiB/s 52.325 MiB/s]
stream/256B             time:   [497.76 ns 498.14 ns 498.53 ns]                        
                        thrpt:  [489.72 MiB/s 490.11 MiB/s 490.48 MiB/s]
stream/1KiB             time:   [1.3219 µs 1.3223 µs 1.3228 µs]                         
                        thrpt:  [738.23 MiB/s 738.51 MiB/s 738.77 MiB/s]
stream/16KiB            time:   [6.9246 µs 6.9280 µs 6.9320 µs]                          
                        thrpt:  [2.2012 GiB/s 2.2025 GiB/s 2.2036 GiB/s]
stream/1MiB             time:   [428.69 µs 429.00 µs 429.33 µs]                        
                        thrpt:  [2.2746 GiB/s 2.2764 GiB/s 2.2780 GiB/s]

aead/16B                time:   [530.08 ns 530.30 ns 530.56 ns]                      
                        thrpt:  [28.760 MiB/s 28.774 MiB/s 28.786 MiB/s]
aead/256B               time:   [733.51 ns 733.84 ns 734.18 ns]                       
                        thrpt:  [332.54 MiB/s 332.69 MiB/s 332.84 MiB/s]
aead/1KiB               time:   [1.6208 µs 1.6214 µs 1.6222 µs]                       
                        thrpt:  [601.99 MiB/s 602.29 MiB/s 602.53 MiB/s]
aead/16KiB              time:   [7.2486 µs 7.2532 µs 7.2579 µs]                        
                        thrpt:  [2.1024 GiB/s 2.1037 GiB/s 2.1051 GiB/s]
aead/1MiB               time:   [430.35 µs 430.85 µs 431.38 µs]                      
                        thrpt:  [2.2638 GiB/s 2.2666 GiB/s 2.2693 GiB/s]
```

(Benchmarks run on a GCE `n2-standard-4` with an Intel Ice Lake CPU.)
