var fs = require("fs")
var sqlite3 = require("cross-sqlcipher-promise")
var kc
var sanitize = require("sanitize-filename")
var tmp = require("tmp")
var crypto = require("crypto")

var SESSIONDIR = "" 
var USERDIR = ""
/*
  Session:
  Create(user,password) => Promise->token
  KeyLookup(token,name) => Promise->key
  Destroy(token) => Promise->bool
  UserPassword(token) => Promise->{user, password}
*/
function SQLEncode(str) {
    return  (""+str).replace(/'/g,"''")
}

// ->Promise->token
function SessionCreate(user,passwd,_) {
    user = user.replace(/[^A-Za-z0-9_]/gmi,"")
    passwd = SQLEncode(passwd)
    // first check if user file exists
    if (!fs.existsSync(USERDIR+user)) {
	return new Promise((resolve,reject)=>resolve(""))
    }
    // test access
    var db = new sqlite3.Database(USERDIR+user), db2
    var session,bkey,data
    return db.exec("PRAGMA cipher_default_kdf_iter='64000';").then(()=>{
	return db.exec("PRAGMA KEY='"+passwd+"';")
    }).then(()=>{
	return db.get("SELECT * FROM SQLITE_MASTER")
    }).then(d=>{
	data=d
	return db.close()
    }).then(()=>{
	if (!data) {
	    throw ""
	}
	var tmp1 = tmp.fileSync({template:(SESSIONDIR+"XXXXXX"),keep:true})
	var akey = crypto.randomBytes(32)
	bkey = akey.slice(0,32).toString("hex")
	session=tmp1.name
	return new Promise((resolve)=> {
	    fs.close(tmp1.fd,()=>{resolve()})
	})
    }).then(()=> {
	db2 = new sqlite3.Database(session)
	db2.serialize()
	var ret = db2.exec("PRAGMA KEY=\"x'"+bkey+"'\"")
	return ret
    }).then(()=>{
	return db2.run("CREATE TABLE keys(name TEXT PRIMARY KEY,password);")
    }).then(()=> {
	return db2.run("INSERT INTO keys(name,password) VALUES (?,?)",[user,passwd])
    }).then(row=> {
	return db2.close()
    }).then(()=> {
	return session.slice(session.length-6)+bkey
    }).catch(e=>{
	console.log(e)
	return ""
    })
}

function SessionDestroy(token) {
    return SessionUserPasswd(token).then(up=>{
	if (!up) return false
	var session = token.slice(0,6)
	if (!fs.existsSync(SESSIONDIR+session)) return false
	fs.unlinkSync(SESSIONDIR+session)
	return true
    })
}

// token is 6 byte filename followed by 64 byte hex key
function SessionUserPasswd(token) {
    //-> { user:string user, passwd:string passwd }
    var session = token.slice(0,6)
    var akey = token.slice(6,64+6).replace(/[^A-Fa-f0-9]/gmi,"")
    if (akey.length != 64 || session != sanitize(session)) {
	return new Promise((resolve,reject)=>resolve(false))
    }
    if (!session || !fs.existsSync(SESSIONDIR+session)) {
	return new Promise((resolve,reject)=>resolve(false))
    }
    var db = new sqlite3.Database(SESSIONDIR+session)
    var q = "PRAGMA KEY=\"x'"+akey+"'\"",data
    return db.exec(q).then(()=> {
	return db.get("SELECT name,password FROM keys")
    }).then(d=> {
	data=d
	return db.close()
    }).then(()=> {
	return {user:data.name,passwd:data.password}
    })
}

function SessionKeyLookup(token,name) {
    return SessionUserPasswd(token).then(up=>{
	if (!up) return up
	return kc.Get(up.user,up.passwd)
    }).then(db=>{
	return kc.Lookup(db,name)
    })
}

function SessionKeyAdd(token,res,passwd) {
    return SessionUserPasswd(token).then(up=>{
	if (!up) return up
	return kc.Get(up.user,up.passwd)
    }).then(db=>{
	return kc.Add(db,res,passwd)
    })
}

module.exports = function(config) {
    if (typeof config == "object") {
	if ("sessiondir" in config) {
	    SESSIONDIR = config.sessiondir
	}
	if ("userdir" in config) {
	    USERDIR = config.userdir
	}
    }
    kc = require("keychain-promise")({dir:USERDIR})
    return {
	Create:SessionCreate,
	Destroy:SessionDestroy,
	KeyLookup:SessionKeyLookup,
	KeyAdd:SessionKeyAdd,
	UserPassword:SessionUserPasswd
    }
}
