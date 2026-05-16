//! Optional C ABI for embedding `marlinspike-dpi` in non-Rust applications.
//!
//! The ABI stays intentionally small: callers pass raw capture bytes and get a
//! JSON string back. That keeps the stable boundary at the serialization layer
//! rather than exposing Rust-native Bronze structs over FFI. The exported
//! symbol names remain `fm_dpi_*` for Fathom compatibility.

use std::ffi::{CStr, CString, c_char};
use std::io::Cursor;
use std::ptr;

use serde::Serialize;

use crate::{DpiEngine, DpiSegmentOutput};

#[repr(C)]
pub struct FmDpiProcessResult {
    pub json_ptr: *mut c_char,
    pub error_ptr: *mut c_char,
}

#[derive(Serialize)]
struct JsonEnvelope<'a> {
    output: &'a DpiSegmentOutput,
}

fn into_c_string_ptr(value: String) -> *mut c_char {
    let sanitized = value.replace('\0', "\\u0000");
    CString::new(sanitized)
        .expect("sanitized string must not contain interior nulls")
        .into_raw()
}

fn error_result(message: impl Into<String>) -> FmDpiProcessResult {
    FmDpiProcessResult {
        json_ptr: ptr::null_mut(),
        error_ptr: into_c_string_ptr(message.into()),
    }
}

fn success_result(payload: String) -> FmDpiProcessResult {
    FmDpiProcessResult {
        json_ptr: into_c_string_ptr(payload),
        error_ptr: ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `capture_id` must be a valid, non-null, NUL-terminated UTF-8 C string.
/// `data_ptr` must be non-null and valid for reads of `data_len` bytes for the
/// duration of the call.
pub unsafe extern "C" fn fm_dpi_process_pcapng_json(
    capture_id: *const c_char,
    data_ptr: *const u8,
    data_len: usize,
) -> FmDpiProcessResult {
    if capture_id.is_null() {
        return error_result("capture_id must not be null");
    }

    if data_ptr.is_null() {
        return error_result("data_ptr must not be null");
    }

    let capture_id = match unsafe { CStr::from_ptr(capture_id) }.to_str() {
        Ok(value) if !value.is_empty() => value,
        Ok(_) => return error_result("capture_id must not be empty"),
        Err(_) => return error_result("capture_id must be valid UTF-8"),
    };

    let payload = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
    let mut engine = DpiEngine::new();
    let output = match engine
        .process_capture_to_vec(&crate::SegmentMeta::new(capture_id), Cursor::new(payload))
    {
        Ok(output) => output,
        Err(error) => return error_result(error.to_string()),
    };

    match serde_json::to_string(&JsonEnvelope { output: &output }) {
        Ok(json) => success_result(json),
        Err(error) => error_result(format!("failed to serialize Bronze output: {error}")),
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `ptr` must either be null or a pointer returned by this crate from
/// `fm_dpi_process_pcapng_json` via `CString::into_raw`. It must not be freed
/// more than once.
pub unsafe extern "C" fn fm_dpi_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        drop(CString::from_raw(ptr));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn fm_dpi_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};

    use super::{fm_dpi_process_pcapng_json, fm_dpi_string_free};

    #[test]
    fn ffi_rejects_empty_capture_id() {
        let capture_id = CString::new("").unwrap();
        let bytes = [0u8; 4];

        let result =
            unsafe { fm_dpi_process_pcapng_json(capture_id.as_ptr(), bytes.as_ptr(), bytes.len()) };

        assert!(result.json_ptr.is_null());
        assert!(!result.error_ptr.is_null());

        let error = unsafe { CStr::from_ptr(result.error_ptr) }
            .to_str()
            .unwrap()
            .to_string();
        assert!(error.contains("capture_id must not be empty"));

        unsafe { fm_dpi_string_free(result.error_ptr) };
    }

    #[test]
    fn ffi_reports_decode_errors() {
        let capture_id = CString::new("capture-1").unwrap();
        let bytes = [1u8, 2, 3, 4];

        let result =
            unsafe { fm_dpi_process_pcapng_json(capture_id.as_ptr(), bytes.as_ptr(), bytes.len()) };

        assert!(result.json_ptr.is_null());
        assert!(!result.error_ptr.is_null());

        let error = unsafe { CStr::from_ptr(result.error_ptr) }
            .to_str()
            .unwrap()
            .to_string();
        assert!(!error.is_empty());

        unsafe { fm_dpi_string_free(result.error_ptr) };
    }
}
