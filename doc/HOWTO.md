

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
 * [Namespace management](#namespace-management)
 * [Authorization policies](#authorization-policies)
 * [Secret types](#secret-types)
 * [Data persistence](#data-persistence)
 * placeholder: Cluster management
 * placeholder: Internals

## Configuring the server
Before you start the server, you might want to take a look at its configuration.
It is not mandatory to look at it when you're just starting to experiment with
the system, but it's a good idea to understand some of the configuration
properties. Before going over the properties though, let's understand where the
server expects to find its configuration file.

The server expects a file called "config.yaml" in its current directory
(the directory from which you're starting the server). This is why, in the VSM
root dir, you start the server with "./dist/vsmd". In the future we will add
a command-line switch to control where the server configuration should be loaded
from; until then you need to make sure the configuration file is in the current
directory.

Now let's go over some of the main configuration properties (open "config.yaml"):
```
# Server
server:

  # Listeners
  http:
    enabled: true
    port: 8080
  https:
    enabled: true
    port: 8443

    # Root server certificate, also used to sign certificates when the server acts as a Certificate Authority
    caCert: certs/test-root-cert.pem

    # Private key corresponding to root server certificate
    caKey:  certs/test-root-key.pem

    # Certificate used by the server in SSL handshake. Must be signed by key in caKey
    serverCert: certs/test-server-cert.pem

    # Private key of serverCert
    serverKey: certs/test-server-key.pem

  # Public key to create user "root" during server initialization
  rootInitPubKey: certs/test-root-init-public.pem

  # Private key of user "root". Recommended to remove from server when moving from testing to production.
  rootInitPriKey: certs/test-root-init-private.pem

# Data Store - this is where encrypted secrets are stored
dataStore:
  type: InMemoryDataStore
  connectionString:

# Virtual Key Store - manages keys' storage and retrieval
virtualKeyStore:
  # Number of key stores
  keyStoreCount: 3

  # Minimum number of key stores required to create and retrieve keys
  keyStoreThreshold: 2

  # Key stores that will keep the actual keys
  keyStores:
  - type: InMemoryKeyStore
    connectionString:
  - type: InMemoryKeyStore
    connectionString:
  - type: InMemoryKeyStore
    connectionString:
```

* **http** and **https** - both of them are enabled by default, which means the
  server will accept both types of connections. This is convenient in testing
  and experimentation. In production we recommend disabling http and enabling
  only https. You can control the ports that the server listens on through
  **port**.
* **Certificates** - when **https** is enabled, a number of certificates are
  expected:
  
    **caCert** - points to the file containing the root CA certificate. By
    default, this would be **"certs/test-root-cert.pem"**, which is a self-signed
    certificate bundled with the system. In production replace this with your
    own root CA certificate.  
    **caKey** - points to the file containing the root CA private key.  
    **serverCert** - points to the file containing the server certificate, i.e.
    the certificate that is being used by the server in https connections. This
    certificate must be signed by the root CA, and indeed, the default server
    certificate (**"certs/test-server-cert.pem"**) is signed by the default
    root CA.  
    **serverKey** - points to the file containing the private key corresponding
    to the server certificate. By default it is **"certs/test-server-key.pem"**
    
* **rootInitPubKey** - points to the file containing the public key of the
  server's root user, which is created once during initialization of a new
  server. By default it is **"certs/test-root-init-public.pem"**; however in
  production you'd want to replace that with your own public key **before
  starting the server** so that you're the only one who has the corresponding
  root user private key (as opposed to **"certs/test-root-init-private.pem"**,
  which is available to everyone).
* **dataStore** - controls the type and location of the server's data store,
    where (encrypted) data is persisted. By default we use an in-memory data
    store, which is convenient for testing and experimentation.
* **virtualkeyStore** - controls the number of configured key stores,
    the minimum number of key stores required for creation and retrival of
    secrets, and the key stores' configuration (type and location of each
    key store, where encryption keys' shares are persisted. By default we use an
    in-memory key store, which is convenient for testing and experimentation).
 
Once you've gone through the exprimentation phase, you should take a look at
[Data persistence](#data-persistence) to understand how to configure a persistent
data store and persistent key stores.

## Starting the server
If the server, "vsmd", is already built, you can start it
**from a directory containing the server's configuration file ("config.yaml")**:
```
./dist/vsmd
```
## Browsing the API documentation
The server supports a RESTful API, which is documented using
[Swagger](http://swagger.io/). The server's swagger specification file is
**"swagger.json"**, which resides in the "doc" dir (if it's not there, you
need to generate it using "make doc"). There are multiple tools for loading
and browsing a Swagger spec; we've successfully tested the procedure described
at http://swagger.io/docs/ (look for "Swagger UI Documentation"), as follows:

```
make doc-serve
```

Will spin up a http server to serve the "swagger.json" file. The port on which
the server listens on will be printed on the screen:

```
swagger serve --no-open /.../swagger.json
2017/03/23 14:09:05 serving docs at http://:::33998/docs
```

In our example the port number is 33998.
Now launch a web browser and open <swagger-ui-root>/dist/index.html.
Replace the address at the top according to your port number:

```
http://localhost:33998/swagger.json
```

You should be able to browse the API documentation.


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
* -u, --url: you can provide the server's URL (both http and https are
  supported). The default is "http://localhost:8080", which works in the default
  test configuration. You can also use "https://localhost:8443" with the default
  test configuration.
* -c, --cert: points to the filename containing the root CA public key. This
  is not needed with the default test config, because the client will use
  "certs/test-root-cert.pem" - the test root CA public key - if the option is
  omitted; however you will need it in case the server has a non-default root CA
  certificate.

Let's give it a try - make sure the server is started and then run:
```
./vsm-cli secrets create data hello world
```
This should fail with an error message like: "authn token is empty". You need to
provide an auth token. But to get a token you need to log-in, which we haven't
covered yet. In the next section we'll show you how to log-in, grab the generated
token and use it in your further interactions with the server.

## Logging in
To log-in you need to have an existing user. If you haven't created a user yet,
that's fine (in fact, you have to be logged-in to create a user, so this is kind of
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
for root is similar to the authentication of other users - you need to provide the
private key. The default root private key (which corresponds to the default root
public key) is in "../certs/test-root-init-private.pem" so try this:
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

You will use the token in your further interaction with the server. Try:
```
./vsm-cli --token $TOKEN users get root
```

You should see the returned root user info.

## User management
Logging-in as root is fine, but it's dangerous - as root you can perform any action on
any object. So typically root will create additional users and delegate them certain
permissions. User management allows you to:
* Create a user
* Get a user's info
* Delete a user

Note: you can also list existing users through [namespaces](#namespace-management).

Let's start by creating a user. To create a user you need to specify a username
and credentials - a public key in the case of the built-in authn provider. So
let's generate a RSA key-pair first. We'll use [openssl](https://www.openssl.org/)
for that:

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

Now, just to illustrate the point of all this, let's log-in as test-user:
```
./vsm-cli login test-user test-user-private.pem
```

You should get a new token - one that represents the test-user's 'session'. You can use
this new token to perform operations on-behalf of test-user, but we don't need this for
now, so we're actually going to delete the user:

```
./vsm-cli --token $TOKEN users delete test-user
```

## Secret management
In this section we're going to create secrets and manage their life-cycle. Finally!

let's start by creating a secret:
```
./vsm-cli --token $TOKEN secrets create data coke-secret-formula "7X"
```

We have created a data secret entry whose key is "core-secret-formula" and its value
is "7X". A data secret is a secret of type "Data", which is the simplest secret type -
it's not interpreted by the system. We will learn about additional secret types later.

Let's verify that we can reconstruct the secret:

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

## Namespace management
VSM is a multi-tenant system. The primary construct that enables multi-tenancy
is: namespace. The secrets namespace starts at "/secrets" and can be partitioned
into multiple sub-namespaces, hierarchically. For example, let's create two
sub-namespaces directly under "/secrets", then, in the first sub-namespace
we'll create a secret and in the second sub-namespace we'll create a third
sub-namespace and a secret in it:

```
./vsm-cli --token $TOKEN namespaces create /secrets/sub1
./vsm-cli --token $TOKEN namespaces create /secrets/sub2
./vsm-cli --token $TOKEN namespaces create /secrets/sub2/sub3
./vsm-cli --token $TOKEN secrets create data sub1/first-secret hello-first
./vsm-cli --token $TOKEN secrets create data sub2/sub3/second-secret hello-second
```

Now try to read the secrets:
```
./vsm-cli --token $TOKEN secrets get sub1/first-secret
./vsm-cli --token $TOKEN secrets get sub2/sub3/second-secret
```

You should be able to retrieve the secrets.

Of course, just partitioning a namespace is not enough for multi-tenancy - you
need to be able to segregate each namespace. We'll do that when we learn about
authorization.

Namespaces in general do not need to live under "/secrets" - they are a more
fundamental mechanism within VSM, which uses them for its own management; for
example: users are created under the "/users" namespace. You can check this
out, for example list all users through the namespaces command:

```
./vsm-cli --token $TOKEN namespaces get /users
```

All namespaces live under the root namespace "/", and all secrets live under
"/secrets".

## Authorization policies
VSM supports a rich RBAC model. Here's an overview:

* A **role** is a **role label** associated with a **role scope**, where a role
  label is a string (e.g." administrator") and a role scope is a namespace path
  (e.g. "/secrets/coke")
* A **namespace** can declare multiple *role label*s. For example, the namespace
  "/secrets/coke" can declare the role labels "administrator" and "visitor".
* A **user** can be assigned multiple **role**s, i.e. pairs of **role label**
  and **role scope**.
* Finally, an **Authorization Policy** is contained within a **namespace**
  and specifies thet certain *role*s are allowed certain **operation**s (an
  operation is one of "C" (**C**reate), "R" (**R**ead), "U" (**U**pdate) or
  "D" (**D**elete))
  
When an operation **op** is attempted at resource **res** which requires authorization,
the following check kicks-in:

1. The identity of the user who's attempting **op** is determined (authentication).
2. If the user is **root**, access is granted
3. The namespace which contains **res** is determined
4. If the namespace contains an authorization policy, access will be determined
   based on the policy(ies) in that namespace. Otherwise, the namespace parent
   is searched for authorization policies, recursively up to the root namespace
   ("/"). If no namespace contains an authorization policy, access is denied.
   To be clear: If a namespace containing an authorization policy is found, the
   search up the namespace path is stopped.
5. Each policy in the namespace is evaluated against **op** and **res**. If at least
   one policy grants access, then access is granted. A policy grants access if
   and only if the following 2 conditions are **both** met: the user has a role
   that is visible in the namespace (i.e. a a role whose scope is the namespace
   or an ancestor namespace) **and** the operation **op** is included in the
   set of operations allowed by the policy.
   
Let's practice that using an example. We will create:

* 2 namespaces: "/secrets/namespace1" and "/secrets/namespace2".
* In the first namespace, we will create 2 roles, "admin" and "user"; and 2
  policies: an "admin-is-king" policy which allows "admin" to perfrom any
  operation and a "user-can-read" policy which allows "user" to read.
* In the second namespace, we will create 1 role, "admin" and an "admin-is-king"
  policy which allows that role to perform any operation.
* 2 users: "user1" and "user2". We will assign user1 the role "admin" in the
  first namespace. We will assign user2 the role "user" in the first namespace
  and the role "admin" in the second namespace.
* We will then show that:

     * user1 can create and read a secret in "/secrets/namespace1".
     * user2 can create and read a secret in "/secrets/namespace2".
     * user2 can read an existing secret in "/secrets/namespace1" but
       not delete it nor create a new secret in that namespace.
     * user1 cannot perform any operation in "/secrets/namespace2".
     
Ready? here we go:

Let's create the namespaces with their role labels (**you need to be logged in as
root**):
```
./vsm-cli --token $TOKEN namespaces create /secrets/namespace1 user1 "admin,user"
./vsm-cli --token $TOKEN namespaces create /secrets/namespace2 user2 "admin"
```

Now let's create the policies:
```
./vsm-cli --token $TOKEN authz create /secrets/namespace1/admin-is-king admin "C,R,U,D"
./vsm-cli --token $TOKEN authz create /secrets/namespace1/user-can-read user "R"
./vsm-cli --token $TOKEN authz create /secrets/namespace2/admin-is-king admin "C,R,U,D"
```

Let's create the users with their roles:
```
openssl genrsa -out user1-private.pem 2048
openssl rsa -in user1-private.pem -outform PEM -pubout -out user1-public.pem
./vsm-cli --token $TOKEN users create user1 user1-public.pem "/secrets/namespace1:admin"

openssl genrsa -out user2-private.pem 2048
openssl rsa -in user2-private.pem -outform PEM -pubout -out user2-public.pem
./vsm-cli --token $TOKEN users create user2 user2-public.pem "/secrets/namespace1:user,/secrets/namespace2:admin"
```

Now let's try some operations as user1. **Open a new window and log-in as user1**:
```
./vsm-cli login user1 user1-private.pem
...
TOKEN="..."
./vsm-cli --token $TOKEN secrets create data namespace1/user1-secret user1-data
./vsm-cli --token $TOKEN secrets get namespace1/user1-secret
```

Now let's try some operations as user2. **Open a new window and log-in as user2**:
```
./vsm-cli login user2 user2-private.pem
...
TOKEN="..."
./vsm-cli --token $TOKEN secrets create data namespace2/user2-secret user2-data
./vsm-cli --token $TOKEN secrets get namespace2/user2-secret
./vsm-cli --token $TOKEN secrets get namespace1/user1-secret
```

Note that the last command succeeded because the "user-can-read" policy in
"/secrets/namespace1" allowed it!

Now let's try some commands that **should fail**:  

user1 should not be able to perform any operation in namespace2:
```
./vsm-cli --token $TOKEN secrets get namespace2/user2-secret
...
Response status is different than 200 StatusOK: 403 Forbidden
``` 

user2 should not be able to delete or create a secret in namespace1:
```
./vsm-cli --token $TOKEN secrets delete namespace1/user1-secret
...
Response status is different than 201 StatusCreated: 403 Forbidden
...
./vsm-cli --token $TOKEN secrets create data namespace1/user2-secret user2-data
...
Response status is different than 201 StatusCreated: 403 Forbidden
```

## Secret types
So far we've dealt with one type of secret: a data secret. With a data
secret the client provides the secret data and can retrieve it; the server
does not understand the nature of the data.

Sometimes it's beneficial to create typed secrets, that the server understands.
Two such secret types are **RSA Private Key** and **X509 Certificate**. We're
going to demonstrate the value of those through an example:

Let's generate a RSA private key (note that we're providing the key length):
```
./vsm-cli --token $TOKEN secrets create rsa-private-key pk1 2048
```

Unlike using client-side tools like openssl, when you're using VSM to create
a private key, the private key stays in VSM. Of course, you're allowed to retrieve
your own private key, so let's do that:
```
./vsm-cli --token $TOKEN secrets get pk1
```

You should see the PEM-encoding of the private key you've created.

Now let's create a certificate that corresponds to the private key you've created
(note that you need to provide, in addition to the certificate id, the id of the
private key and additional parameters like common name, organization and country):
```
./vsm-cli --token $TOKEN secrets create x509-certificate cert1 pk1 my.example.com example-org US
``` 

The certificate you've created lives in the server as well, and it wraps the public key that
corresponds to the private key you've created.

The certificate is signed by the VSM server acting as a CA (Certificate Authority). If you configure
clients to trust certificates signed by the VSM server, VSM acts as a CA in your environment.

Note: you must have read access to the private key in order to generate the certificate - this is
to prevent you claiming ownership of a public key you don't own!

Let's retrieve the certificate:
```
./vsm-cli --token $TOKEN secrets get cert1
```

You should see the PEM-encoded certificate. You can grab it and paste it in
https://www.sslshopper.com/certificate-decoder.html to view the details of your certificate.

## Data persistence
To enable data persistence you need to configure the server's Data Store Adapter and Key Store Adapters in
the virtualKeyStore section of the configuration.

Let's start with the Data Store Adapter: VSM supports any data store that satisfies the DataStoreAdapter interface.
There are two implementations currently available (beyond the in-memory one):
* **MongoDBDataStore** - an adapter to MongoDB (https://www.mongodb.com/)
* **CassandraDataStore** - an adapter to Apache Cassandra (http://cassandra.apache.org/)

To use the MongoDBDataStore adapter, you need to stand up a MongoDB server. The easiet way to do
that is using the standard MongoDB docker image from Docker Hub (https://hub.docker.com/_/mongo/). Once
your MongoDB is up and running you need to provide its address (IP address or DNS name) to the VSM server. For
example, if your MongoDB server IP address is 172.17.0.2, then you should set the following in "config.yaml":

```
dataStore:
  type: MongoDBDataStore
  connectionString: 172.17.0.2
```

The MongoDBDataStore adapter suppors more advanced settings:
* You can specify a customer write concern for write operations.

For example:
```
connectionString: 172.17.0.2,172.17.0.3,172.17.0.4;write_concern=MultipleDC
```

To use the CassandraDataStore adapter, you need to stand up a Cassandra cluster. The easiet way to do
that is using the standard Cassandra docker image from Docker Hub (https://hub.docker.com/_/cassandra/). Once
your Cassandra is up and running you need to provide its address (IP address or DNS name) to the VSM server. For
example, if your Cassandra server IP address is 172.17.0.2, then you should set the following in "config.yaml":

```
dataStore:
  type: CassandraDataStore
  connectionString: 172.17.0.2
```

You need to create the VSM schema in Cassandra. Connect to your Cassandra using cqlsh and invoke:

```
CREATE KEYSPACE vsm WITH replication = {'class': 'SimpleStrategy', 'replication_factor' : 1};
CREATE TABLE vsm.vsm_entries (id text PRIMARY KEY, parent_id text, data blob, meta_data text);
```

This will create the vsm keyspace and its vsm_entries table in Cassandra.

The CassandraDataStore adapter suppors more advanced settings:
* You can filter the datacenter of hosts to connect to using the "datacenter" attribute in the connection string
* You can set the consistency level of operations using the "consistency" attribute in the connection string

For example:
```
connectionString: 192.168.211.138;datacenter=uswest;consistency=LOCAL_QUORUM
```


Now let's continue to the Key Store Adapters. VSM supports any key store that satisfies the KeyStoreAdapter interface.
The only implementation currently available (beyond the in-memory one), is "BoltKeyStore", which is an adapter based
on Bolt (https://github.com/boltdb/bolt). On a per Key Store Adapter basis you need to set config settings (type and
connectionString). In the case of BoltKeyStore, the type is "BoltKeyStore" and the connectionString is the filename
where data will be kept. For example:
```
virtualKeyStore:
  # Number of key stores
  keyStoreCount: 3

  # Minimum number of key stores required to create and retrieve keys
  keyStoreThreshold: 2

  # Key stores that will keep the actual keys
  keyStores:
  - type: BoltKeyStore
    connectionString: ks1.db
  - type: BoltKeyStore
    connectionString: ks2.db
  - type: BoltKeyStore
    connectionString: ks3.db
```

After configuring the data store and key stores restart the VSM server.
