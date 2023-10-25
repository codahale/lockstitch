#![no_main]
use libfuzzer_sys::fuzz_target;
use lockstitch::Protocol;

fuzz_target!(|data: &[u8]| {
    let mut hash = Protocol::new("lockstitch.fuzz.hash");
    hash.mix(data);
    let _ = hash.derive_array::<32>();
});
