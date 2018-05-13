Cross-Platform SQLCipher based session tokens
=======================================

# Overview

This package presents a session abstraction.  A session is an SQLite database encrypted by a temporary random key.  It contains the user's name (which identifies their keychain [keychain](https://github.com/michael-ts/keychain-promise)) and password (which is used to decrypt that keychain). An opaque session token is generated which is presented to locate and decrypt the session database to obtain the user's name and password which can then be used to decrypt the keychain in order to gain access to encrypted resources requested by the user.

This session mechanism provides for authentication in situation in which the server is only semi-trusted, specifically when other users may have read access to all the data.  All resources on the server are encrypted by a totally random key not known to anybody but stored in the user's keychain encrypted with a key based on their password.  In this way, not only is read access of data on the server useless to anybody not an authorized user, but shared access can easily be revoked, since users only know the key to unlock their keychains, and not the actual encrpytion keys themselves.


# Usage

In the following example, create a session for user "michael" with password "12345".  Then look up the
password or key for resource "test".  Print the password, then destroy the session and display whether or
not this was successful.

```
var session = require("./index.js")()
var token
var x = session.Create("michael","12345").then(tok=>{
  token=tok
  return session.KeyLookup(token,"test")
}).then(key=> {
  console.log("key=",key)
  return session.Destroy(token)
}).then(ok=>{
  console.log("destroyed=",ok)
})
```

# API


## Instantiation

```
var kc = require("session-promise")(options)
```
If options is present, it is expected to be an object.  The following keys are recognized:

```userdir```: string path to the directory containing all user keychains
```sessiondir```: string path to the directory containing all session files

If either option is missing, the current directory is used.

## Create
```
Create(user,password)
=> Promise->token
```
Given a valid user name and password corresponding to a keychain, create a new session for that user and
return a promise resolving to a string token representing the session.  If invalid credentials are passed the token will be the empty string.

## Destroy
```
Destroy(token)
=> Promise->bool
```
Given a session token, invalidate the session.  Returns a promise resolving to a boolean indicating success or failure.

## UserPassword
```
UserPassword(token)
=> Promise->{ user:user, passwd: password }
```
Given a session token, return a promise resolving to an object containing two keys: "user" and "password" which contain the user name and password, respectively, associated with the session.

## KeyLookup
```
KeyLookup(token,name)
=> Promise->key
```
Given a session token and a keychain name, returns a promise resolving to the key in the keychain for the resource with the specified name.

