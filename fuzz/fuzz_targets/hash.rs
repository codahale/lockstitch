#![no_main]
use libfuzzer_sys::fuzz_target;
use lockstitch::Protocol;

fuzz_target!(|message: &[u8]| {
    let mut hash = Protocol::new("lockstitch.fuzz.hash");
    hash.mix(b"message", message);
    let _ = hash.derive_array::<32>(b"digest");
});
