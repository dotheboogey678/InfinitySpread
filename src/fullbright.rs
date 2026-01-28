#[cfg(target_arch = "x86_64")]
const SMALL_PATCH_SIGNATURES: &[&str] = &[
    "E3 03 19 2A E4 03 14 AA A5 00 80 52 08 05 00 51", //4 places to patch to make sure the liquid spreads infinity in all 4 directions.
    "E3 03 19 2A 29 05 00 51 E4 03 14 AA 65 00 80 52", //This is only for 1.21.123 arm64. I don't know if it will work for previous versions.
    "E3 03 19 2A E4 03 14 AA 85 00 80 52 08 05 00 11",
    "E3 03 19 2A 29 05 00 11 E4 03 14 AA 45 00 80 52",
];

pub fn patch_gfx_gamma() -> Result<(), &'static str> {
    let mut patched_addrs = Vec::new();

    for signature in SMALL_PATCH_SIGNATURES.iter() {
        loop {
            if let Some(addr) = resolve_signature(signature) {
                // Skip already patched addresses
                if patched_addrs.contains(&addr) {
                    break;
                }

                unsafe {
                    use region::{protect, Protection};

                    protect(addr, 4, Protection::READ_WRITE_EXECUTE)
                        .map_err(|_| "Memory protection failed")?;

                    std::ptr::write_unaligned(addr as *mut u32, 0x52800003);

                    clear_cache::clear_cache(addr, addr.add(4));

                    protect(addr, 4, Protection::READ_EXECUTE).ok();
                }

                patched_addrs.push(addr);
            } else {
                break;
            }
        }
    }

    Ok(())
}

fn resolve_signature(signature: &str) -> Option<*mut u8> {
    unsafe {
        let sig_cstr = std::ffi::CString::new(signature).ok()?;
        let mod_cstr = std::ffi::CString::new("libminecraftpe.so").ok()?;

        let result = crate::preloader::pl_resolve_signature(
            sig_cstr.as_ptr() as *const u8,
            mod_cstr.as_ptr() as *const u8,
        );

        if result == 0 {
            None
        } else {
            Some(result as *mut u8)
        }
    }
}
