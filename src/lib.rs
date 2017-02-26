extern crate libc;
extern crate pamsm;

mod yk;

use yk::{Yubikey, Cmd, Slot};
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

struct Args {
    debug: bool,
    slot: yk::Slot,
}

fn parse_args(args: Vec<String>) -> Option<Args> {
    let mut debug = false;
    let mut slot = None;
    for a in args {
        let mut bits = a.splitn(2, '=');
        match bits.next() {
            None => return None,
            Some("debug") => debug = bits.next().map(|v| v == "true").unwrap_or(true),
            Some("slot") => slot = bits.next().and_then(|v| if v == "1" {
                Some(Slot::Slot1)
            } else if v == "2" {
                Some(Slot::Slot2)
            } else {
                None
            }),
            Some(_) => return None,
        }
    }
    slot.map(|s| Args {
        debug: debug,
        slot: s,
    })
}

impl PamServiceModule for SM {
    fn authenticate(self: &Self, pamh: Pam, _: PamFlag, args: Vec<String>) -> PamError {
        let args = match parse_args(args) {
            None => {
                println!("pam_ykchallenge error, missing or bad argument. Usage : pam_ykchallenge slot=<1|2> [debug=true]");
                return PamError::SERVICE_ERR;
            }
            Some(a) => a,
        };

        let yk = match Yubikey::new() {
            Some(yk) => yk,
            None => {
                debug!(args.debug, "pam_ykchallenge error, no yubikey found");
                return PamError::CRED_INSUFFICIENT;
            }
        };

        let (major, minor) = yk.version();
        if major < 2 || (major == 2 && minor <= 2) {
            debug!(args.debug, "pam_ykchallenge error, only yubikey 2.2 and upwards support challenge-response");
            return PamError::CRED_INSUFFICIENT;
        }

        match pamh.get_authtok(None) {
            Ok(None) => {
                debug!(args.debug, "No credentials available");
                PamError::AUTHINFO_UNAVAIL
            }
            Ok(Some(token)) => {
                match yk.challenge_response(args.slot, Cmd::HMAC, token.to_bytes()) {
                    Some(mut resp) => {
                        // We use the hex representation of the response as the token.
                        // This is easier to tinker with it manually and ensure we
                        // don't have any null bytes in the token.
                        // new yubikeys seem to support a 28 byte output, while older one only return 20 bytes.
                        let hexresp = match resp.tohexstring(Some(20)) {
                            Err(e) => {
                                debug!(args.debug, "pam_ykchallenge error, converting challenge response to hexstring : {}", e);
                                return PamError::SERVICE_ERR;
                            }
                            Ok(resp) => resp,
                        };
                        debug!(args.debug, "Response from challenge : {:?}", hexresp);
                        match pamh.set_authtok(&hexresp) {
                            Err(e) => {
                                debug!(args.debug, "pam_ykchallenge error, re-setting the authentication token : {}", e);
                                PamError::SERVICE_ERR
                            }
                            Ok(_) => PamError::SUCCESS,
                        }
                    }
                    None => {
                        debug!(args.debug, "pam_ykchallenge error, no answer from yubikey, check your slot configuration");
                        PamError::SERVICE_ERR
                    }
                }
            }
            Err(e) => {
                debug!(args.debug, "pam_ykchallenge error, retrieving authentication token : {}", e);
                PamError::SERVICE_ERR
            }
        }
    }
}


#[no_mangle]
pub extern "C" fn get_pam_sm() -> Box<PamServiceModule> {
    return Box::new(SM {});
}

