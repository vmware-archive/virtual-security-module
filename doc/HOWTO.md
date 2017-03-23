

# virtual-security-module: HOW TO

## Overview
In this section we're going to provide information about how to accomplish some common tasks with VSM:

 * [Configuring the server](#configuring-the-server)
 * [Starting the server](#starting-the-server)
 * [Browsing the API documentation](#browsing-the-api-documentation)
 * [Using the cli tool](#using-the-cli-tool)
 * [Logging in](#logging-in)
 * [User management](#user-management)
 * [Secret management](#secret-management)
 * placeholder: auto-rotating secrets
 * placeholder: Namespace management
 * placeholder: Authorization policies
 * placeholder: Cluster management
 * placeholder: Internals

## Configuring the server
Before you start the server, you might want to take a look at its configuration
file. It is not mandatory to look at it when you're just starting to experiment
with the system, but it's a good idea to understand some of the configuration
options. Before going over the options though, let's understand where the server
expects to find its configuration file.

The server expects to a filed called "config.yaml" in its current directory
(the directory from which you're starting the server). This is why, in the VSM
root dir, you start the server with "./dist/vsmd". In the future we will add
a command-line switch to control where the server configuration should be loaded
from; until then you need to make sure the configuration file is in the current
directory.

Now let's go over some of the main configuration properties (open "config.yaml"):
* **http** and **https** - both of them are enabled by default, which means the
  server will accept both types of connections. This is convenient in testing
  and experimentation. In production we recommend disabling http and enabling
  only https. You can control the ports that the server listens on through
  **port**.
* **Certificates** - when **https** is enabled, a number of certificates are
  expected:
  ** **caCert** - points to the file containing the root CA certificate. By
    default, this would be **"certs/test-root-cert.pem"**, which is a self-signed
    certificate bundled with the system. In production replace this with your
    own root CA certificate.
  ** **caKey** - points to the file containing the root CA private key.
  ** **serverCert** - points to the file containing the server certificate, i.e.
    the certificate that is being used by the server in https connections. This
    certificate must be signed by the root CA, and indeed, the default server
    certificate (**"certs/test-server-cert.pem"**) is signed by the default
    root CA.
  ** **serverKey** - points to the file containing the private key corresponding
    to the server certificate. By default it is **"certs/test-server-key.pem"**
  ** **rootInitPubKey** - points to the file containing the public key of the
    server's root user, which is created once during initialization of a new
    server. By default it is **"certs/test-root-init-public.pem"**; however in
    production you'd want to replace that with your own public key **before
    starting the server** so that you're the only one who has the corresponding
    root user private key (as opposed to **"certs/test-root-init-private.pem"**,
    which is available to everyone).
* **dataStore** - controls the type and location of the server's data store,
    where (encrypted) data is persisted. By default we use an in-memory data
    store, which is convenient for testing and experimentation.
* **keyStore** - controls the type and location of the server's virtual
    key store, where encryption keys are persisted. By default we use an
    in-memory key store, which is convenient for testing and experimentation.
 

## Starting the server
If the server, "vsmd", is already built, you can start it
**from a directory containing the server's configuration file ("config.yaml")**:
```
./dist/vsmd
```
## Browsing the API documentation
The server supports a RESTful API, which is documented using
[Swagger](http://swagger.io/). The server's swagger specification file is
**"swagger.json"**, which resides in the root dir (if it's not there, you need
to generate it using "make doc"). There are multiple tools for loading and
browsing a Swagger spec; we've successfully tested the procedure described
at http://swagger.io/docs/ (look for "Swagger UI Documentation").

## Using the cli tool
The cli tool is called **"vsm-cli"**, and is available in <root-dir>/dist.
It can be run from anywhere though. For the purpose of this document we will assume
you've cd into <root-dir>/dist so the cli tool can be invoked using:
```
./vsm-cli
```

Go ahead and run the cli tool - you should see a bunch of commands and top-level
options.

Here are a few important top-level options:
* -t, --token: you must provide a valid JWT token for interaction with the server.
  You receive a JWT token after successfully logging into the server.
* -u, --url: you can provide the server's URL (both http and https is are
  supported). The default is "http://localhost:8080", which works in the default
  test configuration. You can also use "https://localhost:8443" with the default
  test configuration.
* -c, --cert: points to the filename containing the root CA public key. This
  is not needed with the default test config, because the client will use
  "certs/test-root-cert.pem", the test root CA public key, if the option is
  omitted, however you will need it in case the server has a non-default root CA
  certificate.

Let's give it a try - make sure the server is started and then run:
```
./vsm-cli secrets create hello world
```
This should fail with an error message like: "authn token is empty". You need to
provide an auth token. But to get a token you need to log-in, which we haven't
cover yet. In the next section we'll show you how to log-in, grab the generated
token and use it in your further interactions with the server.

## Logging in
To log-in you need to have an existing user. If you haven't created a user yet,
that's fine (in fact, you have be logged-in to create a user, so this is kind of
a recursive problem) - the server has already initialized itself with a root user.
The name of the root user is "root" and its credentials is a public key, taken
from the file pointed by the "rootInitPubKey" configuration property
("certs/test-root-init-public.pem" by default).

This is a good time to pause and explain how user authentication works in VSM:
The system supports a pluggable authentication framework. The default
authentication provider, aka "built-in provider", relies on public key
cryptography. A user is created with a username and a public key, and during
authentication the user needs to provide her username and private key.

The root user has a fixed user name, "root", but other than that authentication
for root is similar to authenticating other users - you need to provide root's
private key. The default root private key (which corresponds to the default root
public key is in "../certs/test-root-init-private.pem" so try this:
```
./vsm-cli login root ../certs/test-root-init-private.pem
```

You should see an output like the following:
```
Login successful
Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0OTAxMTQ2NzcsIm5hbWUiOiJyb290In0.laGMmM0bAzxGFN7dCw8LL-bFVzDdvuWR-cAhTZcl6Zo
```

Though the token value will probably be different. You will need that token value,
so copy it into your clipboard now or save it in an environment variable, like TOKEN. 
Through the rest of the document, we will assume $TOKEN holds your authentication token.
Please note that the token will expire in one hour - you will need to log-in again
to get a new token to continue interacting with the server.

You will use the token in your further authentication with the server. Try:
```
./vsm-cli --token $TOKEN users get root
```

You should see the returned root user info.

## User management
Loggin in as root is fine, but it's dangerous - as root you can perform any action on
any object. So typically root will create additional users and delegate them certain
permissions. User management allows you to:
* Create a user
* Get a user's info
* Delete a user

In the future we're going to add support for listing existing users.

Let's start by creating a user. To create a user you need to specify a username
(the username has to be globally unique in the system, so it's convenient to use
an email address) and credentials (a public key in the case of the built-in
authn provider). So let's generate a RSA key-pair first. We'll use
[openssl](https://www.openssl.org/) for that:

```
openssl genrsa -out test-user-private.pem 2048
```
 
a "test-user-private.pem" file should have been created. Now let's extract the
public key:
```
openssl rsa -in test-user-private.pem -outform PEM -pubout -out test-user-public.pem
```

A "test-user-public.pem" file should have been created. Now we can create a user:
```
./vsm-cli --token $TOKEN users create test-user test-user-public.pem 
```

If that was successful you've just created your first user!
Note that we used the public key for creating the user - it is the public
key that is being sent to the server, not the private one. You should keep
the private key to yourself - it proves the user's identity!!

Let's verify the existence of the user:

```
./vsm-cli --token $TOKEN users get test-user
```

You should see some details about the user.

Now, just to illustrate the point of all this, let's login as test-user:
```
./vsm-cli login test-user ~/tmp/test-user-private.pem
```

You should get a new token - one that represents the test-user's 'session'. You can use
this new token to perform operations on-behalf of test-user, but we don't need this for
now, so we're actually going to delete the user:

```
./vsm-cli --token $TOKEN users delete test-user
```

## Secret Management
In this section we're going to create secrets and manage their life-cycle. Finally!

let's start by creating a secret:
```
./vsm-cli --token $TOKEN secrets create coke-secret-formula "7X"
```

We have created a secret entry whose key is "core-secret-formula" and its value
is "7X". Let's verify that we can reconstruct the secret:

```
./vsm-cli --token $TOKEN secrets get coke-secret-formula
```

You should see the secret data (value) in the output.

So what's the big deal? the deal is that the secret data is encrypted and the
encryption key is not persisted anywhere - it is broken down to pieces and
the each piece is saved in a different place. But we're going to cover that
in the [Internals] section.

We can create additional secrets and retrieve them. Finally, we can delete a
secret by providing its key:

```
./vsm-cli --token $TOKEN secrets delete coke-secret-formula
```
