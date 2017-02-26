extern crate libc;
extern crate pamsm;

mod yk;

use yk::Yubikey;
use pamsm::{PamServiceModule, Pam};
use pamsm::pam_raw::{PamFlag, PamError};

struct SM;

macro_rules! debug {
    ($debug:expr, $( $arg:expr ),*) => {
        if $debug {
            println!($( $arg, )*)
        }
    }
}

impl PamServiceModule for SM {
    fn authenticate(self: &Self, pamh: Pam, _: PamFlag, args: Vec<String>) -> PamError {
        let debug = args.len() >= 1 && args[0] == "debug";

        let yk = Yubikey::new().unwrap();
        let (major, minor) = yk.version();
        println!("yubikey version {}.{}", major, minor);
        match pamh.get_authtok(None) {
            Ok(None) => {
                debug!(debug, "No credentials available");
                PamError::AUTHINFO_UNAVAIL
            }
            Ok(Some(_)) => {
                PamError::SUCCESS
            }
            Err(e) => {
                debug!(debug, "Error retrieving authentication token : {}", e);
                PamError::SERVICE_ERR
            }
        }
    }
}


#[no_mangle]
pub extern "C" fn get_pam_sm() -> Box<PamServiceModule> {
    return Box::new(SM {});
}

