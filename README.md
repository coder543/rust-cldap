# openldap

[![Build Status](https://travis-ci.org/sholsapp/rust-cldap.svg?branch=master)](https://travis-ci.org/sholsapp/rust-cldap)

Rust bindings for the native OpenLDAP library with a few convenient
abstractions for connecting, binding, configuring, and querying your LDAP
server.

## usage

Using openldap is as easy as the following.

```
static LDAP_URI: &'static str = "ldaps://localhost:636";

static LDAP_USER: &'static str = "user";

static LDAP_PASS: &'static str = "pass";

fn main() {
    let ldap = try!(RustLDAP::new(LDAP_URI));

    ldap.set_option(codes::options::LDAP_OPT_PROTOCOL_VERSION,
                    &codes::versions::LDAP_VERSION3);

    ldap.set_option(codes::options::LDAP_OPT_X_TLS_REQUIRE_CERT,
                    &codes::options::LDAP_OPT_X_TLS_DEMAND);

    try!(ldap.simple_bind(LDAP_USER, LDAP_PASS));

    // Returns a LDAPResponse, a.k.a. Vec<HashMap<String,Vec<String>>>.
    let res = ldap.simple_search(
        "CN=Stephen,OU=People,DC=Earth",
        codes::scopes::LDAP_SCOPE_BASE,
    ).unwrap();
}
```

When performing an operation that can fail, use the `try!` macro. On failure,
an `openldap::errors::LDAPError` will be returned that includes a detailed
message from the native OpenLDAP library.

## developers

To author new changes to this library, do XYZ.
