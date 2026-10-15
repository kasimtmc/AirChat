#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| airchat_core::fuzz::chat_message(data));
