//! Objects for connecting and querying LDAP servers using `OpenLDAP`.
//!
//! Current support includes connection, initializing, binding, configuring, and search against an
//! LDAP directory.
//!
extern crate libc;
use libc::{c_int, c_char, c_void, timeval};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::ptr;
use std::slice;
use std::boxed;

pub mod codes;
pub mod errors;

#[repr(C)]
struct LDAP;

#[repr(C)]
struct LDAPMessage;

#[repr(C)]
pub struct LDAPControl;

#[repr(C)]
struct BerElement;

unsafe impl Sync for LDAP {}
unsafe impl Send for LDAP {}

#[link(name = "lber")]
#[allow(improper_ctypes)]
extern "C" {
    fn ber_free(ber: *const BerElement, freebuf: c_int);
}

#[link(name = "ldap_r")]
#[allow(improper_ctypes)]
extern "C" {
    static ber_pvt_opt_on: c_char;
    fn ldap_initialize(ldap: *mut *mut LDAP, uri: *const c_char) -> c_int;
    fn ldap_memfree(p: *mut c_void);
    fn ldap_msgfree(msg: *mut LDAPMessage) -> c_int;
    fn ldap_err2string(err: c_int) -> *const c_char;
    fn ldap_first_entry(ldap: *mut LDAP, result: *mut LDAPMessage) -> *mut LDAPMessage;
    fn ldap_next_entry(ldap: *mut LDAP, entry: *mut LDAPMessage) -> *mut LDAPMessage;
    fn ldap_get_dn(ldap: *mut LDAP, entry: *mut LDAPMessage) -> *const c_char;
    fn ldap_get_values(ldap: *mut LDAP,
                       entry: *mut LDAPMessage,
                       attr: *const c_char)
                       -> *const *const c_char;
    fn ldap_count_values(vals: *const *const c_char) -> c_int;
    fn ldap_value_free(vals: *const *const c_char);
    fn ldap_set_option(ldap: *const LDAP, option: c_int, invalue: *const c_void) -> c_int;
    fn ldap_simple_bind_s(ldap: *mut LDAP, who: *const c_char, pass: *const c_char) -> c_int;
    fn ldap_first_attribute(ldap: *mut LDAP,
                            entry: *mut LDAPMessage,
                            berptr: *mut *mut BerElement)
                            -> *const c_char;
    fn ldap_next_attribute(ldap: *mut LDAP,
                           entry: *mut LDAPMessage,
                           berptr: *mut BerElement)
                           -> *const c_char;
    fn ldap_search_ext_s(ldap: *mut LDAP,
                         base: *const c_char,
                         scope: c_int,
                         filter: *const c_char,
                         attrs: *const *const c_char,
                         attrsonly: c_int,
                         serverctrls: *mut *mut LDAPControl,
                         clientctrls: *mut *mut LDAPControl,
                         timeout: *mut timeval,
                         sizelimit: c_int,
                         res: *mut *mut LDAPMessage)
                         -> c_int;
    fn ldap_unbind_ext_s(ldap: *mut LDAP,
                         sctrls: *mut *mut LDAPControl,
                         cctrls: *mut *mut LDAPControl)
                         -> c_int;
}

/// A typedef for an `LDAPResponse` type.
///
/// LDAP responses are organized as vectors of mached entities. Typically, each entity is
/// represented as a map of attributes to list of values.
///
pub type LDAPResponse = Vec<HashMap<String, Vec<String>>>;


/// A high level abstraction over the raw `OpenLDAP` functions.
///
/// A `RustLDAP` object hides raw `OpenLDAP` complexities and exposes a simple object that is
/// created, configured, and queried. Methods that call underlying `OpenLDAP` calls that can fail
/// will raise an `errors::LDAPError` with additional details.
///
/// Using a `RustLDAP` object is easy!
///
pub struct RustLDAP {
    /// A pointer to the underlying `OpenLDAP` object.
    ldap_ptr: *mut LDAP,
}


unsafe impl Sync for RustLDAP {}
unsafe impl Send for RustLDAP {}

impl Drop for RustLDAP {
    fn drop(&mut self) {
        // Unbind the LDAP connection, making the C library free the LDAP*.
        let rc = unsafe { ldap_unbind_ext_s(self.ldap_ptr, ptr::null_mut(), ptr::null_mut()) };

        // Make sure it actually happened.
        if rc != codes::results::LDAP_SUCCESS {
            unsafe {
                // Hopefully this never happens.
                let raw_estr = ldap_err2string(rc as c_int);
                panic!(CStr::from_ptr(raw_estr).to_owned().into_string().unwrap());
            }
        }
    }
}

/// A trait for types that can be passed as LDAP option values.
///
/// Underlying `OpenLDAP` implementation calls for option values to be passed in as `*const c_void`,
/// while allowing values to be `i32` or `String`. Using traits, we implement function overloading to
/// handle `i32` and `String` option value types.
///
/// This trait allocates memory that a caller must free using `std::boxed::Box::from_raw`. This
/// helps guarantee that there is not a use after free bug (in Rust) while providing the appearance
/// of opaque memory to `OpenLDAP` (in C). In pure C, we would've accomplished this by casting a
/// local variable to a `const void *`. In Rust, we must do this on the heap to ensure Rust's
/// ownership system does not free the memory used to store the option value between now and when
/// the option is actually set.
///
pub trait LDAPOptionValue {
    fn as_cvoid_ptr(&self) -> *const c_void;
}

impl LDAPOptionValue for str {
    fn as_cvoid_ptr(&self) -> *const c_void {
        let string = CString::new(self).unwrap();
        string.into_raw() as *const c_void
    }
}

impl LDAPOptionValue for i32 {
    fn as_cvoid_ptr(&self) -> *const c_void {
        let mem = boxed::Box::new(*self);
        boxed::Box::into_raw(mem) as *const c_void
    }
}

impl LDAPOptionValue for bool {
    fn as_cvoid_ptr(&self) -> *const c_void {
        if *self {
            let mem = unsafe { boxed::Box::new(&ber_pvt_opt_on) };
            boxed::Box::into_raw(mem) as *const c_void
        } else {
            let mem = boxed::Box::new(0);
            boxed::Box::into_raw(mem) as *const c_void
        }
    }
}

impl RustLDAP {
    /// Create a new `RustLDAP`.
    ///
    /// Creates a new `RustLDAP` and initializes underlying `OpenLDAP` library. Upon creation, a
    /// subsequent calls to `set_option` and `simple_bind` are possible. Before calling a search
    /// related function, one must bind to the server by calling `simple_bind`. See module usage
    /// information for more details on using a `RustLDAP` object.
    ///
    /// # Parameters
    ///
    /// * uri - URI of the LDAP server to connect to. E.g., ldaps://localhost:636.
    ///
    pub fn new(uri: &str) -> Result<RustLDAP, errors::LDAPError> {

        // Create some space for the LDAP pointer.
        let mut cldap = ptr::null_mut();

        let uri_cstring = CString::new(uri).unwrap();

        unsafe {
            let res = ldap_initialize(&mut cldap, uri_cstring.as_ptr());
            if res != codes::results::LDAP_SUCCESS {
                let raw_estr = ldap_err2string(res as c_int);
                return Err(errors::LDAPError::NativeError(CStr::from_ptr(raw_estr)
                                                              .to_owned()
                                                              .into_string()
                                                              .unwrap()));
            }

        }

        Ok(RustLDAP { ldap_ptr: cldap })
    }

    /// Sets an option on the LDAP connection.
    ///
    /// When setting an option to _ON_ or _OFF_ one may use the boolean values `true` or `false`,
    /// respectively.
    ///
    /// # Parameters
    ///
    /// * option - An option identifier from `cldap::codes`.
    /// * value - The value to set for the option.
    ///
    pub fn set_option<T: LDAPOptionValue + ?Sized>(&self, option: i32, value: &T) -> bool {
        let ptr: *const c_void = value.as_cvoid_ptr();
        unsafe {
            let res: i32;
            res = ldap_set_option(self.ldap_ptr, option, ptr);
            // Allows for memory to be dropped when this binding goes away.
            let _ = boxed::Box::from_raw(ptr as *mut c_void);
            res == 0
        }
    }

    /// Bind to the LDAP server.
    ///
    /// If you wish to configure options on the LDAP server, be sure to set required options using
    ///`set_option` _before_ binding to the LDAP server. In some advanced cases, it may be required
    /// to set multiple options for an option to be made available. Refer to the `OpenLDAP`
    /// documentation for information on available options and how to use them.
    ///
    /// # Parameters
    ///
    /// * who - The user's name to bind with.
    /// * pass - The user's password to bind with.
    ///
    pub fn simple_bind(&self, who: &str, pass: &str) -> Result<i32, errors::LDAPError> {
        let who_cstr = CString::new(who).unwrap();
        let pass_cstr = CString::new(pass).unwrap();
        let who_ptr = who_cstr.as_ptr();
        let pass_ptr = pass_cstr.as_ptr();
        unsafe {
            let res = ldap_simple_bind_s(self.ldap_ptr, who_ptr, pass_ptr);
            if res < 0 {
                let raw_estr = ldap_err2string(res as c_int);
                return Err(errors::LDAPError::NativeError(CStr::from_ptr(raw_estr)
                                                              .to_owned()
                                                              .into_string()
                                                              .unwrap()));
            }
            Ok(res)
        }
    }

    /// Simple synchronous search.
    ///
    /// Performs a simple search with only the base, returning all attributes found.
    ///
    /// # Parameters
    ///
    /// * base - The LDAP base.
    /// * scope - The search scope. See `cldap::codes::scopes`.
    ///
    pub fn simple_search(&self, base: &str, scope: i32) -> Result<LDAPResponse, errors::LDAPError> {
        self.ldap_search(base,
                         scope,
                         None,
                         None,
                         false,
                         None,
                         None,
                         ptr::null_mut(),
                         -1)
    }

    /// Advanced synchronous search.
    ///
    /// Exposes a raw API around the underlying `ldap_search_ext_s` function from `OpenLDAP`.
    /// Wherever possible, use provided wrappers.
    ///
    /// # Parameters
    ///
    /// * base - The base domain.
    /// * scope - The search scope. See `cldap::codes::scopes`.
    /// * filter - An optional filter.
    /// * attrs - An optional set of attrs.
    /// * attrsonly - True if should return only the attrs specified in `attrs`.
    /// * serverctrls - Optional sever controls.
    /// * clientctrls - Optional client controls.
    /// * timeout - A timeout.
    /// * sizelimit - The maximum number of entities to return, or -1 for no limit.
    ///
    pub fn ldap_search(&self,
                       base: &str,
                       scope: i32,
                       filter: Option<&str>,
                       attrs: Option<Vec<&str>>,
                       attrsonly: bool,
                       serverctrls: Option<*mut *mut LDAPControl>,
                       clientctrls: Option<*mut *mut LDAPControl>,
                       timeout: *mut timeval,
                       sizelimit: i32)
                       -> Result<LDAPResponse, errors::LDAPError> {

        // Make room for the LDAPMessage, being sure to delete this before we return.
        let mut ldap_msg = ptr::null_mut();

        // Convert the passed in filter sting to either a C-string or null if one is not passed.
        let filter_cstr: CString;
        let r_filter = match filter {
            Some(fs) => {
                filter_cstr = CString::new(fs).unwrap();
                filter_cstr.as_ptr()
            }
            None => ptr::null(),
        };

        // Convert the vec of attributes into the null-terminated array that the library expects.
        let mut r_attrs: *const *const c_char = ptr::null();
        let mut c_strs: Vec<CString> = Vec::new();
        let mut r_attrs_ptrs: Vec<*const c_char> = Vec::new();

        if let Some(strs) = attrs {
            for string in strs {
                // Create new CString and take ownership of it in c_strs.
                c_strs.push(CString::new(string).unwrap());
                // Create a pointer to that CString's raw data and store it in r_attrs.
                r_attrs_ptrs.push(c_strs[c_strs.len() - 1].as_ptr());
            }
            // Ensure that there is a null value at the end of the vector.
            r_attrs_ptrs.push(ptr::null());
            r_attrs = r_attrs_ptrs.as_ptr();
        }

        let r_serverctrls = match serverctrls {
            Some(sc) => sc,
            None => ptr::null_mut(),
        };

        let r_clientctrls = match clientctrls {
            Some(cc) => cc,
            None => ptr::null_mut(),
        };

        let base = CString::new(base).unwrap();

        unsafe {
            let res: i32 = ldap_search_ext_s(self.ldap_ptr,
                                             base.as_ptr(),
                                             scope as c_int,
                                             r_filter,
                                             r_attrs,
                                             attrsonly as c_int,
                                             r_serverctrls,
                                             r_clientctrls,
                                             timeout,
                                             sizelimit as c_int,
                                             &mut ldap_msg);
            if res != codes::results::LDAP_SUCCESS {
                let raw_estr = ldap_err2string(res as c_int);
                return Err(errors::LDAPError::NativeError(CStr::from_ptr(raw_estr)
                                                              .to_owned()
                                                              .into_string()
                                                              .unwrap()));
            }
        }

        // We now have to parse the results, copying the C-strings into Rust ones making sure to
        // free the C-strings afterwards
        let mut resvec: Vec<HashMap<String, Vec<String>>> = vec![];
        let mut entry = unsafe { ldap_first_entry(self.ldap_ptr, ldap_msg) };

        while !entry.is_null() {

            // Make the map holding the attribute : value pairs as well as the BerElement that keeps
            // track of what position we're in
            let mut map: HashMap<String, Vec<String>> = HashMap::new();
            let mut ber: *mut BerElement = ptr::null_mut();
            unsafe {
                // Populate the "DN" of the user
                let raw_dn = ldap_get_dn(self.ldap_ptr, entry);
                let mut dn: Vec<String> = Vec::new();
                dn.push(CStr::from_ptr(raw_dn)
                            .to_owned()
                            .into_string()
                            .unwrap_or("<Invalid DN>".to_string()));
                map.insert("dn".to_string(), dn);
                ldap_memfree(raw_dn as *mut c_void);

                let mut attr: *const c_char = ldap_first_attribute(self.ldap_ptr, entry, &mut ber);

                while !attr.is_null() {

                    // Convert the attribute into a Rust string.
                    let key = CStr::from_ptr(attr).to_owned().into_string().unwrap();

                    // Get the attribute values from LDAP.
                    let raw_vals: *const *const c_char =
                        ldap_get_values(self.ldap_ptr, entry, attr);
                    let raw_vals_len = ldap_count_values(raw_vals) as usize;
                    let val_slice: &[*const c_char] = slice::from_raw_parts(raw_vals, raw_vals_len);

                    // Map these into a vector of Strings.
                    let values: Vec<String> = val_slice.iter()
                        .map(|ptr| {
                            // TODO(sholsapp): If this contains binary data this will fail.
                            CStr::from_ptr(*ptr)
                                .to_owned()
                                .into_string()
                                .unwrap_or("<cannot parse binary data yet.>".to_string())
                        })
                        .collect();

                    // Insert newly constructed Rust key-value strings.
                    map.insert(key, values);

                    // Free the attr and value, then get next attr.
                    ldap_value_free(raw_vals);
                    ldap_memfree(attr as *mut c_void);
                    attr = ldap_next_attribute(self.ldap_ptr, entry, ber)
                }

                // Free the BerElement and advance to the next entry.
                ber_free(ber, 0);
                entry = ldap_next_entry(self.ldap_ptr, entry);

            }

            // Push this entry into the vector.
            resvec.push(map);

        }

        // Make sure we free the message and return the parsed results.
        unsafe { ldap_msgfree(ldap_msg) };

        Ok(resvec)
    }
}

#[cfg(test)]
mod tests {

    use std::ptr;
    use codes;

    const TEST_ADDRESS: &'static str = "ldap://ldap.forumsys.com";
    const TEST_BIND_DN: &'static str = "cn=read-only-admin,dc=example,dc=com";
    const TEST_BIND_PASS: &'static str = "password";
    const TEST_SIMPLE_SEARCH_QUERY: &'static str = "uid=tesla,dc=example,dc=com";
    const TEST_SEARCH_BASE: &'static str = "dc=example,dc=com";
    const TEST_SEARCH_FILTER: &'static str = "(uid=euler)";
    const TEST_SEARCH_INVALID_FILTER: &'static str = "(uid=INVALID)";

    /// Test creating a RustLDAP struct with a valid uri.
    #[test]
    fn test_ldap_new() {
        let _ = super::RustLDAP::new(TEST_ADDRESS).unwrap();
    }

    /// Test creating a RustLDAP struct with an invalid uri.
    #[test]
    fn test_invalid_ldap_new() {
        if let Err(e) = super::RustLDAP::new("lda://localhost") {
            assert_eq!(super::errors::LDAPError::NativeError("Bad parameter to an ldap routine"
                                                                 .to_string()),
                       e);
        } else {
            assert!(false);
        }
    }

    #[test]
    #[should_panic]
    fn test_invalid_cstring_ldap_new() {
        let _ = super::RustLDAP::new("INVALID\0CSTRING").unwrap();
    }

    #[test]
    fn test_simple_bind() {
        let ldap = super::RustLDAP::new(TEST_ADDRESS).unwrap();
        assert!(ldap.set_option(codes::options::LDAP_OPT_PROTOCOL_VERSION, &3));
        let res = ldap.simple_bind(TEST_BIND_DN, TEST_BIND_PASS).unwrap();
        assert_eq!(codes::results::LDAP_SUCCESS, res);
        println!("Bind result: {:?}", res);

    }

    #[test]
    fn test_simple_search() {

        println!("Testing simple search");
        let ldap = super::RustLDAP::new(TEST_ADDRESS).unwrap();
        assert!(ldap.set_option(codes::options::LDAP_OPT_PROTOCOL_VERSION, &3));
        let res = ldap.simple_bind(TEST_BIND_DN, TEST_BIND_PASS).unwrap();
        assert_eq!(codes::results::LDAP_SUCCESS, res);
        let search_res =
            ldap.simple_search(TEST_SIMPLE_SEARCH_QUERY, codes::scopes::LDAP_SCOPE_BASE).unwrap();

        //make sure we got something back
        assert!(search_res.len() == 1);

        // make sure the DN is searched and returned correctly
        assert_eq!(search_res[0]["dn"][0], "uid=tesla,dc=example,dc=com");

        for result in search_res {
            println!("simple search result: {:?}", result);
            for (key, value) in result {
                println!("- key: {:?}", key);
                for res_val in value {
                    println!("- - res_val: {:?}", res_val);
                }
            }
        }

    }

    #[test]
    fn test_search() {

        println!("Testing search");
        let ldap = super::RustLDAP::new(TEST_ADDRESS).unwrap();
        assert!(ldap.set_option(codes::options::LDAP_OPT_PROTOCOL_VERSION, &3));
        let res = ldap.simple_bind(TEST_BIND_DN, TEST_BIND_PASS).unwrap();
        assert_eq!(codes::results::LDAP_SUCCESS, res);
        let search_res = ldap.ldap_search(TEST_SEARCH_BASE,
                                          codes::scopes::LDAP_SCOPE_SUB,
                                          Some(TEST_SEARCH_FILTER),
                                          None,
                                          false,
                                          None,
                                          None,
                                          ptr::null_mut(),
                                          -1)
            .unwrap();

        //make sure we got something back
        assert!(search_res.len() == 1);

        // make sure the DN is searched and returned correctly
        assert_eq!(search_res[0]["dn"][0], "uid=euler,dc=example,dc=com");

        for result in search_res {
            println!("search result: {:?}", result);
            for (key, value) in result {
                println!("- key: {:?}", key);
                for res_val in value {
                    println!("- - res_val: {:?}", res_val);
                }
            }
        }

    }

    #[test]
    fn test_invalid_search() {

        println!("Testing invalid search");
        let ldap = super::RustLDAP::new(TEST_ADDRESS).unwrap();
        assert!(ldap.set_option(codes::options::LDAP_OPT_PROTOCOL_VERSION, &3));
        let res = ldap.simple_bind(TEST_BIND_DN, TEST_BIND_PASS).unwrap();
        assert_eq!(codes::results::LDAP_SUCCESS, res);
        let search_res = ldap.ldap_search(TEST_SEARCH_BASE,
                                          codes::scopes::LDAP_SCOPE_SUB,
                                          Some(TEST_SEARCH_INVALID_FILTER),
                                          None,
                                          false,
                                          None,
                                          None,
                                          ptr::null_mut(),
                                          -1)
            .unwrap();

        //make sure we got something back
        assert!(search_res.len() == 0);

    }

    #[test]
    fn test_search_attrs() {

        println!("Testing search with attrs");
        let test_search_attrs_vec = vec!["cn", "sn", "mail"];
        let ldap = super::RustLDAP::new(TEST_ADDRESS).unwrap();
        assert!(ldap.set_option(codes::options::LDAP_OPT_PROTOCOL_VERSION, &3));
        let res = ldap.simple_bind(TEST_BIND_DN, TEST_BIND_PASS).unwrap();
        assert_eq!(codes::results::LDAP_SUCCESS, res);
        let search_res = ldap.ldap_search(TEST_SEARCH_BASE,
                                          codes::scopes::LDAP_SCOPE_SUB,
                                          Some(TEST_SEARCH_FILTER),
                                          Some(test_search_attrs_vec),
                                          false,
                                          None,
                                          None,
                                          ptr::null_mut(),
                                          -1)
            .unwrap();

        //make sure we got something back
        assert!(search_res.len() == 1);

        for result in search_res {
            println!("attrs search result: {:?}", result);
            for (key, value) in result {
                println!("- key: {:?}", key);
                for res_val in value {
                    println!("- - res_val: {:?}", res_val);
                }
            }
        }

    }

    #[test]
    fn test_search_invalid_attrs() {

        println!("Testing search with invalid attrs");
        let test_search_attrs_vec = vec!["cn", "sn", "mail", "INVALID"];
        let ldap = super::RustLDAP::new(TEST_ADDRESS).unwrap();
        assert!(ldap.set_option(codes::options::LDAP_OPT_PROTOCOL_VERSION, &3));
        let res = ldap.simple_bind(TEST_BIND_DN, TEST_BIND_PASS).unwrap();
        assert_eq!(codes::results::LDAP_SUCCESS, res);
        let search_res = ldap.ldap_search(TEST_SEARCH_BASE,
                                          codes::scopes::LDAP_SCOPE_SUB,
                                          Some(TEST_SEARCH_FILTER),
                                          Some(test_search_attrs_vec),
                                          false,
                                          None,
                                          None,
                                          ptr::null_mut(),
                                          -1)
            .unwrap();

        for result in search_res {
            println!("attrs search result: {:?}", result);
            for (key, value) in result {
                println!("- key: {:?}", key);
                for res_val in value {
                    println!("- - res_val: {:?}", res_val);
                }
            }
        }

    }

}
