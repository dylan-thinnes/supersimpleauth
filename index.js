/* authenticator defines authentication middleware and helper functions, namely:
authenticatePassword, which takes a request and checks its password for validity with in-database hashes. On success, it responds to the user with an allocated session token.
authenticateSession, which is middleware which calls next if isSession evaluates to true, and 403/401s otherwise.
isSession returns a Promise which resolves if the username and sessionToken are validly associated with one another (passing in true/false depending on use of memory) and rejects otherwise.
*/
var crypto = require("crypto");
var abstractdb = require("abstractdb");
var Auth = function (databaseType, path, options) {
    if (databaseType === "sqlite") Database = abstractdb("better-sqlite3");
    else if (databaseType == undefined) Database = abstractdb("better-sqlite3");
    else throw "Unrecognized database type passed.";
    this.db = new Database(path, options);
}
module.exports = Auth;

Auth.prototype.init = function () {
    //Define tables
    this.db.sRun("CREATE TABLE sessions (username STRING, token STRING, timestamp INTEGER)");
    this.db.sRun("CREATE TABLE auth (username STRING PRIMARY KEY, salt STRING, key STRING, inviteAllowed INTEGER)");
    this.db.sRun("CREATE TABLE invites (issuer STRING, code STRING)");
}
Auth.prototype.getSaltAndKey = async function (username) {
    return await this.db.aGet("SELECT salt, key FROM auth WHERE username=$username", {
        $username: username
    });
}
Auth.prototype.checkPassword = async function (username, password) {
    var saltAndKey = await this.getSaltAndKey(username);
    if (saltAndKey == undefined || saltAndKey.salt == undefined || saltAndKey.key == undefined) return false;
    var createdKey = crypto.pbkdf2Sync(password, saltAndKey.salt, 100000, 64, "sha512").toString("hex");
    if (saltAndKey.key === createdKey) return true;
    return false;
}
Auth.prototype.newSessionToken = async function (username) {
    var sessionToken = crypto.randomBytes(256).toString("hex");
    var result = await this.db.aRun("INSERT INTO sessions VALUES ($username, $sessionToken, $timestamp)", {
        $username: username,
        $sessionToken: sessionToken,
        $timestamp: Date.now()
    });
    return sessionToken;
}
Auth.prototype.getSessionToken = async function (username) {
    var result = await this.db.aGet("SELECT token FROM sessions WHERE username=$username", {
        $username: username
    });
    if (result != undefined && result.token != undefined) return result.token;
    return await this.newSessionToken(username);
}
Auth.prototype.createUser = async function (username, password) { //createUser first checks if a user with that username exists, if not it creates that user.
    var result = await this.db.aGet("SELECT username FROM auth WHERE username=$username", {
        $username: username
    });
    if (result != undefined) return false;
    var salt = crypto.randomBytes(256).toString("hex");
    await this.db.aRun("INSERT INTO auth VALUES ($username, $salt, $key, $inviteAllowed)", {
        $username: username,
        $salt: salt,
        $key: crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex"),
        $inviteAllowed: 0
    });
    return true;
}
Auth.prototype.useInvite = async function (code) {
    var result = await this.db.aGet("SELECT issuer FROM invites WHERE code=$code", {
        $code: code
    });
    if (result == undefined) return false;
    await this.db.aRun("DELETE FROM invites WHERE code=$code", {
        $code: code
    });
    return true;
}
Auth.prototype.issueInvite = async function (username, password) {
    var result = await Promise.all([
        this.db.aGet("SELECT username FROM auth WHERE username=$username AND inviteAllowed=1", {
            $username: username
        }),
        this.checkPassword(username, password)
    ]);
    var inviteIsAllowed = result[0] != undefined;
    var validPassword = result[1];
    if (inviteIsAllowed === false || validPassword === false) return undefined;
    var code = crypto.randomBytes(8).toString("hex");
    await this.db.aRun("INSERT INTO invites VALUES ($issuer, $code)", {
        $issuer: username,
        $code: code
    });
    return code;
}
Auth.prototype.signup = async function (req, res) {
    var username = req.body.username;
    var password = req.body.password;
    var inviteCode = req.body.inviteCode;
    var overrideInviteCode = req.overrideInviteCode === true ? true : false; //Force overrideInviteCode to be a Boolean to prevent potential type conversion shenanigans
    if (username == undefined || password == undefined || (inviteCode == undefined && !overrideInviteCode)) {
        res.status(400);
        res.end("You have not provided the necessary data to register an account.");
        return false;
    }
    var usernameTooLong = username.length > 30;
    var passwordTooLong = password.length > 100;
    var specialCharsSearch = /([\x00-\x1F]|\s)/;
    var usernameHasSpecialChars = specialCharsSearch.test(username);
    var passwordHasSpecialChars = specialCharsSearch.test(password);
    if (usernameTooLong || passwordTooLong || usernameHasSpecialChars || passwordHasSpecialChars) {
        res.status(400);
        res.end("The password xor/and username provided is/are not valid. Either too long, or containing control characters/whitespace.");
        return false;
    }
    var userAlreadyExists = await this.getSaltAndKey(username) != undefined; //If getSaltAndKey returns undefined then there must be no user with that username
    if (userAlreadyExists) {
        res.status(400);
        res.end("Account with username " + username + " already exists. Account not created.");
        return false;
    }
    var inviteIsValid = await this.useInvite(inviteCode);
    if (!inviteIsValid && !overrideInviteCode) {
        res.status(400);
        res.end("Invite code is not valid.");
        return false;
    }
    await this.createUser(username, password);
    res.status(200);
    res.end("Account with username " + username + " and password " + ("").padStart(password.length, "*") + " registered.");
    return true;
}
Auth.prototype.authenticatePassword = async function (req, res) {
    var username = req.body.username;
    var password = req.body.password;
    if (username !== undefined && password !== undefined) {
        var validLogin = await this.checkPassword(username, password);
        if (validLogin) {
            res.status(200);
            var token = await this.getSessionToken(username);
            res.cookie("username", username);
            res.cookie("sessionToken", token);
            res.end(token);
            return true;
        } else {
            res.status(403);
            res.end("Your credentials do not have authorization for this zone.");
            return false;
        }
    } else {
        res.status(401);
        res.end("You have not supplied any credentials for this zone.");
        return false;
    }
}
Auth.prototype.authenticateSession = async function (req, res, next) {
    var sessionToken = req.cookies.sessionToken;
    var username = req.cookies.username;
    if (username == undefined || sessionToken == undefined) {
        res.status(401);
        res.end("You have not supplied any credentials for this zone.");
        return false;
    }
    var sessionIsValid = await this.isSession(username, sessionToken);
    if (!sessionIsValid) {
        res.status(403);
        res.end("Your credentials do not have the authorization for this zone.");
        return false;
    }
    next();
    return true;
}
Auth.prototype.isSession = async function (username, token) {
    var result = this.db.aGet("SELECT username FROM sessions WHERE token=$token AND username=$username", {
        $username: username,
        $token: token
    });
    if (result) return true;
    else return false;
}
