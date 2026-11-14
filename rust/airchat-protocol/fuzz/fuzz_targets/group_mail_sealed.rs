#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| airchat_protocol::fuzz::group_mail_sealed(data));
