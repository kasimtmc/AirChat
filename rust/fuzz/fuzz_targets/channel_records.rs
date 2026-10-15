#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| airchat_core::fuzz::channel_records(data));
