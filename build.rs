fn main() {
    println!("cargo:rerun-if-changed=src/aegis128l.c");
    cc::Build::new()
        .opt_level(3)
        .flag_if_supported("-Wno-unknown-pragmas")
        .flag_if_supported("-mtune=native")
        .flag_if_supported("-mneon")
        .flag_if_supported("-maes")
        .flag_if_supported("-msse4.1")
        .file("src/aegis128l.c")
        .compile("aegis_aesni");
}
