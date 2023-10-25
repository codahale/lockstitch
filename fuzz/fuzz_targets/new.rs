#![no_main]
use std::str;

use libfuzzer_sys::fuzz_target;
use lockstitch::Protocol;

fuzz_target!(|data: &[u8]| {
    if let Ok(utf8) = str::from_utf8(data) {
        let _ = Protocol::new(utf8);
    }
});
