# openldap

Rust bindings for the native OpenLDAP library with a few convenient
abstractions for connecting, binding, configuring, and querying your LDAP
server.

## usage

Using openldap is as easy as the following.

```rust
extern crate openldap;

use openldap::*;
use openldap::errors::*;

fn some_ldap_function(ldap_uri: &str, ldap_user: &str, ldap_pass: &str) -> Result<(), LDAPError> {
    let ldap = RustLDAP::new(ldap_uri).unwrap();

    ldap.set_option(codes::options::LDAP_OPT_PROTOCOL_VERSION,
                    &codes::versions::LDAP_VERSION3);

    ldap.set_option(codes::options::LDAP_OPT_X_TLS_REQUIRE_CERT,
                    &codes::options::LDAP_OPT_X_TLS_DEMAND);

    ldap.simple_bind(ldap_user, ldap_pass).unwrap();

    // Returns a LDAPResponse, a.k.a. Vec<HashMap<String,Vec<String>>>.
    let _ = ldap.simple_search("CN=Stephen,OU=People,DC=Earth",
                       codes::scopes::LDAP_SCOPE_BASE)
        .unwrap();

    Ok(())
}

fn main() {
    let ldap_uri = "ldaps://localhost:636";
    let ldap_user = "user";
    let ldap_pass = "pass";
    some_ldap_function(ldap_uri, ldap_user, ldap_pass).unwrap();
}
```

### Security

You should use *start_tls* before calling bind to avoid sending credentials in plain text over an untrusted 
network. See https://linux.die.net/man/3/ldap_start_tls_s for more information

```rust
fn some_ldap_function(ldap_uri: &str, ldap_user: &str, ldap_pass: &str) -> Result<(), LDAPError> {
    let ldap = RustLDAP::new(ldap_uri).unwrap();

    ldap.set_option(codes::options::LDAP_OPT_PROTOCOL_VERSION,
                    &codes::versions::LDAP_VERSION3);

    ldap.set_option(codes::options::LDAP_OPT_X_TLS_REQUIRE_CERT,
                    &codes::options::LDAP_OPT_X_TLS_DEMAND);
    ldap.set_option(openldap::codes::options::LDAP_OPT_X_TLS_NEWCTX, &0);

    ldap.start_tls(None, None);

    ldap.simple_bind(ldap_user, ldap_pass).unwrap();

    Ok(())
}    

```
On failure, an `openldap::errors::LDAPError` will be returned that includes a detailed
message from the native OpenLDAP library.

## contributing

I'm happy to accept contributions. If you have work you want to be merged back into `master`, send me a pull request and I will be happy to look at it. I prefer changes which don't break the API, of course, but I'm willing to consider breaking changes.
