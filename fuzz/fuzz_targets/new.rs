#![no_main]
use std::str;

use libfuzzer_sys::fuzz_target;
use lockstitch::Protocol;

fuzz_target!(|domain: &str| {
    let _ = Protocol::new(domain);
});
