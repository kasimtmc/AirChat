#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| airchat_protocol::fuzz::account_answer(data));
