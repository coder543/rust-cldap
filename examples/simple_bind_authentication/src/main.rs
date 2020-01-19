#[macro_use]
extern crate clap;

extern crate openldap;

use openldap::errors::*;
use openldap::*;
use std::ptr;

#[derive(Clap)]
#[clap(
    name = "LDAP simple_bind_authentication with start_tls authentication example",
    author = "Mathias Myrland <jedimemo@gmail.com>",
    version = "0.1.0"
)]
struct AuthOpts {
    #[clap(short = "u")]
    user: String,

    #[clap(short = "p")]
    password: String,
}

fn ldap_with_start_tls(ldap_uri: &str) -> Result<RustLDAP, LDAPError> {
    let ldap = RustLDAP::new(ldap_uri).unwrap();

    ldap.set_option(
        codes::options::LDAP_OPT_PROTOCOL_VERSION,
        &codes::versions::LDAP_VERSION3,
    );

    // WARNING: Normally you would want to verify the server certificate to avoid
    // man in the middle attacks, but for this testing scenario we're using a
    // generated self signed certificate from the docker container.
    //
    // To set up certificate validation, use the LDAP_OPT_X_TLS_CACERT* options
    ldap.set_option(
        codes::options::LDAP_OPT_X_TLS_REQUIRE_CERT,
        &codes::options::LDAP_OPT_X_TLS_NEVER,
    );

    ldap.set_option(openldap::codes::options::LDAP_OPT_X_TLS_NEWCTX, &0);

    ldap.start_tls(None, None)?;

    Ok(ldap)
}

fn do_simple_bind(
    ldap: &RustLDAP,
    ldap_manager_user: &str,
    ldap_manager_pass: &str,
) -> Result<(), LDAPError> {
    let bind_result = ldap.simple_bind(ldap_manager_user, ldap_manager_pass)?;

    match bind_result {
        v if v == openldap::codes::results::LDAP_SUCCESS => Ok(()),
        _ => Err(LDAPError::from(String::from(
            "Authentication with simple bind failed",
        ))),
    }
}

fn ldap_dn_lookup(ldap: &RustLDAP, who: &str) -> Result<String, LDAPError> {
    // Show all DNs matching the description "Human"
    // ldap_search is a powerful query language, look at
    // https://confluence.atlassian.com/kb/how-to-write-ldap-search-filters-792496933.html
    // for an overview
    //
    // This particular filter allows the user to sign in with either
    // uid or email
    let filter = format!("(|(uid={})(mail={}))", who, who);

    match ldap.ldap_search(
        "ou=people,dc=planetexpress,dc=com",
        codes::scopes::LDAP_SCOPE_SUBTREE,
        Some(filter.as_str()),
        Some(vec!["dn"]),
        true,
        None,
        None,
        ptr::null_mut(),
        -1,
    ) {
        Ok(search_results) => {
            for result_map in search_results {
                for result_tuple in result_map {
                    println!("Found result map with key {}", result_tuple.0);
                    for result_data in result_tuple.1 {
                        println!("\t {}", result_data);
                        return Ok(result_data);
                    }
                }
            }

            Err(LDAPError::from(String::from(
                "Authentication with simple bind failed",
            )))
        }
        _ => Err(LDAPError::from(String::from(
            "Authentication with simple bind failed",
        ))),
    }
}

fn main() {
    let options = AuthOpts::parse();
    let user_to_authenticate = options.user;
    let pwd_to_authenticate = options.password;

    let ldap_uri = "ldap://localhost:389";
    let ldap_manager_dn = "cn=Hubert J. Farnsworth,ou=people,dc=planetexpress,dc=com";
    let ldap_manager_pass = "professor";

    let ldap = ldap_with_start_tls(ldap_uri).unwrap();

    // Bind to the LDAP server with the manager account,
    // this is done to perform a search for the DN to
    // use when authenticating the user attempting to
    // sign in. Obviously, the manager credentials should
    // be kept secret, and not be put under version control.
    // In our test scenario, the professor is the manager.
    do_simple_bind(&ldap, ldap_manager_dn, ldap_manager_pass).unwrap();

    if let Ok(fry_dn) = ldap_dn_lookup(&ldap, user_to_authenticate.as_str()) {
        // Now, perform a bind with the DN we found matching the user attempting to sign in
        // and the password provided in the authentication request
        do_simple_bind(&ldap, fry_dn.as_str(), pwd_to_authenticate.as_str()).unwrap();

        println!("Successfully signed in as fry");
    }
}
