## pam_ykchallenge.so

### Description

This service module retrieves the current authentication token,
asks the yubikey to compute the hmac-sha1 of this token,
and re-set the current authentication token to the yubikey response.

The main goal of this module is allow using a yubikey to open/close/resume/suspend
a LUKS volume.

Only the _auth_ module type is provided.

### Options

- debug=[true|false]
  Optional. Turns on debugging if when set to 'true'.

- slot=[1|2]
  Required. Indicates which slot of the yubikey is configured with HMAC-SHA1.

### Example configuration

- In /etc/pam.d/lockscreen

```
auth            required        pam_unix.so
auth            substack        /etc/pam.d/ykchallenge
```

- And in /etc/pam.d/ykchallenge

```
auth    required        pam_ykchallenge.so      slot=2  debug=true
auth    [success=reset] pam_luksresume.so /usr/lib/security/pam_luksresume_helper home_luks debug
```

This example will call luksResume on the `home_luks` volume with the `yubikey_hmac(password)` key
when the user authenticate on the `lockscreen` application.
Some modules tend to be unhappy when the stack authentication
token is modified, so it is advised to use pam_ykchallenge.so in a substack and to reset it
before returning to the main pam stack.

Initial configuration of the luks volume can be done using the `ykchalresp` tool from
[Yubico/yubikey-personalization](https://github.com/Yubico/yubikey-personalization)
