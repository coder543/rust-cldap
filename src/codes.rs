//! LDAP codes from transcribed from ldap.h.
//!

/// Re-export protocol result codes from ldap.h
pub mod results {
    pub static LDAP_SUCCESS: i32                        = 0x00;
    pub static LDAP_OPERATIONS_ERROR: i32               = 0x01;
    pub static LDAP_PROTOCOL_ERROR: i32                 = 0x02;
    pub static LDAP_TIMELIMIT_EXCEEDED: i32             = 0x03;
    pub static LDAP_SIZELIMIT_EXCEEDED: i32             = 0x04;
    pub static LDAP_COMPARE_FALSE: i32                  = 0x05;
    pub static LDAP_COMPARE_TRUE: i32                   = 0x06;
    pub static LDAP_AUTH_METHOD_NOT_SUPPORTED: i32      = 0x07;
    pub static LDAP_STRONG_AUTH_NOT_SUPPORTED: i32      = 0x07;
    pub static LDAP_STRONG_AUTH_REQUIRED: i32           = 0x08;
    pub static LDAP_STRONGER_AUTH_REQUIRED: i32         = 0x08;
    pub static LDAP_PARTIAL_RESULTS: i32                = 0x09;

    pub static LDAP_REFERRAL: i32                       = 0x0a;
    pub static LDAP_ADMINLIMIT_EXCEEDED: i32            = 0x0b;
    pub static LDAP_UNAVAILABLE_CRITICAL_EXTENSION: i32 = 0x0c;
    pub static LDAP_CONFIDENTIALITY_REQUIRED: i32       = 0x0d;
    pub static LDAP_SASL_BIND_IN_PROGRESS: i32          = 0x0e;

    pub static LDAP_NO_SUCH_ATTRIBUTE: i32              = 0x10;
    pub static LDAP_UNDEFINED_TYPE: i32                 = 0x11;
    pub static LDAP_INAPPROPRIATE_MATCHING: i32         = 0x12;
    pub static LDAP_CONSTRAINT_VIOLATION: i32           = 0x13;
    pub static LDAP_TYPE_OR_VALUE_EXISTS: i32           = 0x14;
    pub static LDAP_INVALID_SYNTAX: i32                 = 0x15;

    pub static LDAP_NO_SUCH_OBJECT: i32                 = 0x20;
    pub static LDAP_ALIAS_PROBLEM: i32                  = 0x21;
    pub static LDAP_INVALID_DN_SYNTAX: i32              = 0x22;
    pub static LDAP_IS_LEAF: i32                        = 0x23;
    pub static LDAP_ALIAS_DEREF_PROBLEM: i32            = 0x24;

    pub static LDAP_X_PROXY_AUTHZ_FAILURE: i32          = 0x2f;
    pub static LDAP_INAPPROPRIATE_AUTH: i32             = 0x30;
    pub static LDAP_INVALID_CREDENTIALS: i32            = 0x31;
    pub static LDAP_INSUFFICIENT_ACCESS: i32            = 0x32;

    pub static LDAP_BUSY: i32                           = 0x33;
    pub static LDAP_UNAVAILABLE: i32                    = 0x34;
    pub static LDAP_UNWILLING_TO_PERFORM: i32           = 0x35;
    pub static LDAP_LOOP_DETECT: i32                    = 0x36;

    pub static LDAP_NAMING_VIOLATION: i32               = 0x40;
    pub static LDAP_OBJECT_CLASS_VIOLATION: i32         = 0x41;
    pub static LDAP_NOT_ALLOWED_ON_NONLEAF: i32         = 0x42;
    pub static LDAP_NOT_ALLOWED_ON_RDN: i32             = 0x43;
    pub static LDAP_ALREADY_EXISTS: i32                 = 0x44;
    pub static LDAP_NO_OBJECT_CLASS_MODS: i32           = 0x45;
    pub static LDAP_RESULTS_TOO_LARGE: i32              = 0x46;
    pub static LDAP_AFFECTS_MULTIPLE_DSAS: i32          = 0x47;

    pub static LDAP_VLV_ERROR: i32                      = 0x4c;

    pub static LDAP_OTHER: i32                          = 0x50;
}

pub mod errors {
    /// Re-export api errors codes
    pub static LDAP_SERVER_DOWN: i32                    = -1;
    pub static LDAP_LOCAL_ERROR: i32                    = -2;
    pub static LDAP_ENCODING_ERROR: i32                 = -3;
    pub static LDAP_DECODING_ERROR: i32                 = -4;
    pub static LDAP_TIMEOUT: i32                        = -5;
    pub static LDAP_AUTH_UNKNOWN: i32                   = -6;
    pub static LDAP_FILTER_ERROR: i32                   = -7;
    pub static LDAP_USER_CANCELLED: i32                 = -8;
    pub static LDAP_PARAM_ERROR: i32                    = -9;
    pub static LDAP_NO_MEMORY: i32                      = -10;
    pub static LDAP_CONNECT_ERROR: i32                  = -11;
    pub static LDAP_NOT_SUPPORTED: i32                  = -12;
    pub static LDAP_CONTROL_NOT_FOUND: i32              = -13;
    pub static LDAP_NO_RESULTS_RETURNED: i32            = -14;
    pub static LDAP_MORE_RESULTS_TO_RETURN: i32         = -15; // Deprecated
    pub static LDAP_CLIENT_LOOP: i32                    = -16;
    pub static LDAP_REFERRAL_LIMIT_EXCEEDED: i32        = -17;
    pub static LDAP_X_CONNECTING: i32                   = -18;
}

pub mod filters {
    pub static LDAP_FILTER_AND: u32                     = 0xa0;
    pub static LDAP_FILTER_OR: u32                      = 0xa1;
    pub static LDAP_FILTER_NOT: u32                     = 0xa2;
    pub static LDAP_FILTER_EQUALITY: u32                = 0xa3;
    pub static LDAP_FILTER_SUBSTRINGS: u32              = 0xa4;
    pub static LDAP_FILTER_GE: u32                      = 0xa5;
    pub static LDAP_FILTER_LE: u32                      = 0xa6;
    pub static LDAP_FILTER_PRESENT: u32                 = 0x87;
    pub static LDAP_FILTER_APPROX: u32                  = 0xa8;
    pub static LDAP_FILTER_EXT: u32                     = 0xa9;

    pub static LDAP_FILTER_EXT_OID: u32                 = 0x81;
    pub static LDAP_FILTER_EXT_TYPE: u32                = 0x82;
    pub static LDAP_FILTER_EXT_VALUE: u32               = 0x83;
    pub static LDAP_FILTER_EXT_DNATTRS: u32             = 0x84;

    pub static LDAP_SUBSTRING_INITIAL: u32              = 0x80;
    pub static LDAP_SUBSTRING_ANY: u32                  = 0x81;
    pub static LDAP_SUBSTRING_FINAL: u32                = 0x82;
}

pub mod scopes {
    pub static LDAP_SCOPE_BASE: i32                     = 0x0000;
    pub static LDAP_SCOPE_BASEOBJECT: i32               = 0x0000;
    pub static LDAP_SCOPE_ONELEVEL: i32                 = 0x0001;
    pub static LDAP_SCOPE_ONE: i32                      = 0x0001;
    pub static LDAP_SCOPE_SUBTREE: i32                  = 0x0002;
    pub static LDAP_SCOPE_SUB: i32                      = 0x0002;
    pub static LDAP_SCOPE_SUBORDINATE: i32              = 0x0003;
    pub static LDAP_SCOPE_CHILDREN: i32                 = 0x0003;
    pub static LDAP_SCOPE_DEFAULT: i32                  = -1;
}

pub mod versions {
    pub static LDAP_VERSION1: i32                       = 1;
    pub static LDAP_VERSION2: i32                       = 2;
    pub static LDAP_VERSION3: i32                       = 3;
}

pub mod options {
    pub static LDAP_OPT_API_INFO: i32                   = 0x0000;
    pub static LDAP_OPT_DESC: i32                       = 0x0001;
    pub static LDAP_OPT_DEREF: i32                      = 0x0002;
    pub static LDAP_OPT_SIZELIMIT: i32                  = 0x0003;
    pub static LDAP_OPT_TIMELIMIT: i32                  = 0x0004;
    /* 0x05 - 0x07 are undefined */
    pub static LDAP_OPT_REFERRALS: i32                  = 0x0008;
    pub static LDAP_OPT_RESTART: i32                    = 0x0009;
    /* 0x0a - 0x10 are undefined */
    pub static LDAP_OPT_PROTOCOL_VERSION: i32           = 0x0011;
    pub static LDAP_OPT_SERVER_CONTROLS: i32            = 0x0012;
    pub static LDAP_OPT_CLIENT_CONTROLS: i32            = 0x0013;
    /* 0x14 is undefined */
    pub static LDAP_OPT_API_FEATURE_INFO: i32           = 0x0015;
    /* 0x16 - 0x2f are undefined */
    pub static LDAP_OPT_HOST_NAME: i32                  = 0x0030;
    pub static LDAP_OPT_RESULT_CODE: i32                = 0x0031;
    pub static LDAP_OPT_ERROR_NUMBER: i32               = 0x0031;
    pub static LDAP_OPT_DIAGNOSTIC_MESSAGE: i32         = 0x0032;
    pub static LDAP_OPT_ERROR_STRING: i32               = 0x0032;
    pub static LDAP_OPT_MATCHED_DN: i32                 = 0x0033;
    /* 0x0034 - 0x3fff are undefined */
    pub static LDAP_OPT_SSPI_FLAGS: i32                 = 0x0092;
    pub static LDAP_OPT_SIGN: i32                       = 0x0095;
    pub static LDAP_OPT_ENCRYPT: i32                    = 0x0096;
    pub static LDAP_OPT_SASL_METHOD: i32                = 0x0097;
    pub static LDAP_OPT_SECURITY_CONTEXT: i32           = 0x0099;

    pub static LDAP_OPT_API_EXTENSION_BASE: i32         = 0x4000;

    pub static LDAP_OPT_X_TLS_CACERTDIR: i32            = 0x6003;
    pub static LDAP_OPT_X_TLS_CACERTFILE: i32           = 0x6002;
    pub static LDAP_OPT_X_TLS_CERTFILE: i32             = 0x6004;
    pub static LDAP_OPT_X_TLS_KEYFILE: i32              = 0x6005;
    pub static LDAP_OPT_X_TLS_NEWCTX: i32               = 0x600f;
    pub static LDAP_OPT_X_TLS_REQUIRE_CERT: i32         = 0x6006;

    pub static LDAP_OPT_X_TLS_NEVER: i32                = 0x0000;
    pub static LDAP_OPT_X_TLS_HARD: i32                 = 0x0001;
    pub static LDAP_OPT_X_TLS_DEMAND: i32               = 0x0002;
    pub static LDAP_OPT_X_TLS_ALLOW: i32                = 0x0003;
    pub static LDAP_OPT_X_TLS_TRY: i32                  = 0x0004;
}
