# Simple Bind with start_tls

This example shows how to use simple_bind in combination with start_tls
and a manager account to do a typical user authentication lookup. 

Start TLS is the recommended way to do secure LDAP; ldaps:// on port 636 is deprecated.

## Running

Start the example docker using the start_example_server.sh script from 
the examples directory. Then, from the simple_bind directory, do 

```shell script
cargo run -- -u fry -p fry
``` 

## Steps that are being performed

The first step is to set up the LDAPRust instance, and perform start_tls on it.
This ensures that our communication is encrypted. Note that we are not verifying
the server certificate in this example; this is something you should do in production.

The next step is to simple_bind using our manger accounts DN and password. This
will allow us to perform an ldap_search later on.

Now, we take the incoming user name string, and perform an ldap_search for it.
Note how we are matching either email or username. Our search yields the DN
for the provided credentials.

The last step is to attempt a simple bind with the discovered DN and provided
user password. If all goes well, we are authenticated, otherwise, something
went wrong.  

