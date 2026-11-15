#![no_std]
//! What a C++ compiler calls for a static object's destructor: `__cxa_atexit`
//! and the `__dso_handle` it is passed. A crate of its own, so that each is an
//! archive member of its own (`Cargo.toml`). The registration itself is
//! `guest-sdk`'s, beside the allocator it takes a record from and the teardown
//! that walks the list.

extern "C" {
    /// `guest-sdk`'s registration of `f(arg)`, to run when `main` returns.
    fn __apogee_register_destructor(f: unsafe extern "C" fn(*mut u8), arg: *mut u8) -> i32;
}

/// Register `f(arg)` to run when `main` returns. C++ calls this once for each
/// static object whose type has a non-trivial destructor, after constructing
/// it.
///
/// In a section of its own, which `apogee.ld` looks for: its being in the image
/// is what makes `main` return into the destructors.
///
/// # Safety
/// `f` may be called once with `arg` after `main` returns.
#[no_mangle]
#[link_section = ".text.apogee.cxa_atexit"]
pub unsafe extern "C" fn __cxa_atexit(
    f: unsafe extern "C" fn(*mut u8),
    arg: *mut u8,
    _dso: *mut u8,
) -> i32 {
    __apogee_register_destructor(f, arg)
}

/// The handle `__cxa_atexit`'s last argument points at. A static image is one
/// object, so nothing compares it with another.
#[no_mangle]
#[allow(non_upper_case_globals)]
pub static __dso_handle: u8 = 0;
