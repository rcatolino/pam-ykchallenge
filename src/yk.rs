use libc::{c_int, c_uint, c_char, c_void};
use std::ptr;

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

pub struct Yubikey {
    status: YkStatus,
    handle: YkHandle,
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
