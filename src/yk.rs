use libc::{c_int, c_uint, c_char, c_void};
use std::ffi::CString;
use std::io::Write;
use std::io;
use std::ptr;

#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[derive(Debug)]
enum YkSlotDefs {
	CONFIG = 1,
	NAV = 2,
	CONFIG2 = 3,
	UPDATE1 = 4,
	UPDATE2 = 5,
	SWAP = 6,
	NDEF = 8,
	NDEF2 = 9,
	DEVICE_SERIAL = 0x10,
	DEVICE_CONFIG = 0x11,
	SCAN_MAP = 0x12,
	YK4_CAPABILITIES = 0x13,
	CHAL_OTP1 = 0x20,
	CHAL_OTP2 = 0x28,
	CHAL_HMAC1 = 0x30,
	CHAL_HMAC2 = 0x38,
}

struct YkStatus {
    ptr: *mut c_void,
}

type YkHandle = *const c_void;

impl YkStatus {
    fn new(ykh: YkHandle) -> Option<YkStatus> {
        let mut st = YkStatus {
            ptr: ptr::null_mut(),
        };
        st.ptr = unsafe { ykds_alloc() };
        if st.ptr.is_null() {
            return None;
        }
        unsafe {
            if yk_get_status(ykh, st.ptr) == 0 {
                ykds_free(st.ptr);
                st.ptr = ptr::null_mut();
                return None;
            }
        }
        Some(st)
    }

    fn version_major(&self) -> u8 {
        unsafe {
            ykds_version_major(self.ptr) as u8
        }
    }

    fn version_minor(&self) -> u8 {
        unsafe {
            ykds_version_minor(self.ptr) as u8
        }
    }
}

impl Drop for YkStatus {
    fn drop(&mut self) {
        unsafe {
            ykds_free(self.ptr);
        }
        self.ptr = ptr::null_mut();
    }
}

#[allow(dead_code)]
pub enum Slot {
    Slot1,
    Slot2,
}

#[allow(dead_code)]
pub enum Cmd {
    OTP,
    HMAC,
}

pub struct Yubikey {
    status: YkStatus,
    handle: YkHandle,
}

pub struct ChallResponse([u8; 64]);

impl ChallResponse {
    fn new() -> ChallResponse {
        ChallResponse([0u8; 64])
    }

    pub fn tohexstring(&mut self, cutoff: Option<usize>) -> io::Result<CString> {
        // hex length is two hex char per byte, plus a trailing null byte (added later by CString)
        let length = cutoff.unwrap_or(self.0.len());
        let mut hex = Vec::<u8>::with_capacity(length * 2 + 1);
        for byte in self.0.iter().take(length) {
            write!(hex, "{:02x}", byte)?
        }
        // this cannot contain any null byte anyway
        unsafe {
            Ok(CString::from_vec_unchecked(hex))
        }
    }
}

impl Yubikey {
    pub fn new() -> Option<Yubikey> {
        unsafe {
            if yk_init() == 0 {
                return None;
            }
        }

        //TODO: add an option to choose a particular yubikey.
        //right now we take the first one available.
        let ykh = unsafe { yk_open_key(0) };
        if ykh.is_null() {
            unsafe {
                yk_release();
            }
            return None;
        }

        let yks = match YkStatus::new(ykh) {
            None => {
                unsafe {
                    yk_close_key(ykh);
                    yk_release();
                }
                return None;
            }
            Some(status) => status,
        };

        Some(Yubikey {
            status: yks,
            handle: ykh,
        })
    }

    pub fn version(&self) -> (u8, u8) {
        (self.status.version_major(), self.status.version_minor())
    }

    pub fn challenge_response(&self, slot: Slot, cmd: Cmd, challenge: &[u8]) -> Option<ChallResponse> {
        let ykcmd = match (cmd, slot) {
            (Cmd::HMAC, Slot::Slot1) => YkSlotDefs::CHAL_HMAC1,
            (Cmd::HMAC, Slot::Slot2) => YkSlotDefs::CHAL_HMAC2,
            (Cmd::OTP, Slot::Slot1) => YkSlotDefs::CHAL_OTP1,
            (Cmd::OTP, Slot::Slot2) => YkSlotDefs::CHAL_OTP2,
        };

        let mut response = ChallResponse::new();
        unsafe {
            if yk_challenge_response(self.handle, ykcmd as u8, 1,
                                     challenge.len() as u32,
                                     challenge.as_ptr() as *const c_char,
                                     response.0.len() as u32,
                                     response.0.as_mut_ptr() as *mut c_char) == 0 {
                return None;
            }
        }
        Some(response)
    }
}

impl Drop for Yubikey {
    fn drop(&mut self) {
        unsafe {
            yk_close_key(self.handle);
            yk_release();
        }
    }
}

#[link(name="ykpers-1")]
extern "C" {
    fn yk_init() -> c_int;
    fn yk_release() -> c_int;
    fn yk_open_key(index: c_int) -> YkHandle;
    fn ykds_alloc() -> *mut c_void;
    fn ykds_free(status: *mut c_void);
    fn yk_get_status(yk: YkHandle, status: *mut c_void) -> c_int;
    fn ykds_version_major(status: *const c_void) -> c_int;
    fn ykds_version_minor(status: *const c_void) -> c_int;
    fn yk_close_key(yk: YkHandle) -> c_int;
    fn yk_challenge_response(yk: YkHandle, cmd: u8, may_block: c_int,
				             challenge_len: c_uint, challenge: *const c_char,
				             response_len: c_uint, response: *mut c_char) -> c_int;
}
