#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| airchat_core::fuzz::handshake_answer(data));
