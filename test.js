(async function () {
    var Auth = require("./index.js");
    var auth = new Auth("sqlite", "memory.db", { memory: true });
    var sampleUsername1 = "mark";
    var samplePassword1 = "1234";
    var sampleUsername2 = "jake";
    var samplePassword2 = "abcd";
    var SampleResponse = function (endHandler) { //SampleResponse creates mock expressjs response objects with status and end methods
        this.code = 0;
        this.status = (function (code) {
            this.code = code;
        }).bind(this);
        this.end = endHandler.bind(this);
        this.setHeader = function () {}
        this.cookie = function () {}
    }

    //Database functions should return errors on database errors, such as when their tables aren't yet CREATEd
    try {
        var res = await auth.createUser(sampleUsername1, samplePassword1);
        console.log("Failed: createUser doesn't reject for database error.");
    } catch (e) {
        console.log("Passed: createUser rejects for database error.");
    }
    try {
        var res = await auth.allocateAuthToken(sampleUsername1);
        console.log("Failed: allocateAuthToken doesn't reject for database error.");
    } catch (e) {
        console.log("Passed: allocateAuthToken rejects for database error.");
    }
    try {
        var res = await auth.checkPassword(sampleUsername1, samplePassword1);
        console.log("Failed: checkPassword doesn't reject for database error.");
    } catch (e) {
        console.log("Passed: checkPassword rejects for database error.");
    }
    try {
        var res = await auth.getSaltAndKey(sampleUsername1, samplePassword1);
        console.log("Failed: getSaltAndKey doesn't reject for database error.");
    } catch (e) {
        console.log("Passed: getSaltAndKey rejects for database error.");
    }
    try {
        var res = await auth.issueInvite(sampleUsername1, samplePassword1);
        console.log("Failed: issueInvite doesn't reject for database error.");
    } catch (e) {
        console.log("Passed: issueInvite rejects for database error.");
    }
    try {
        var res = await auth.useInvite(sampleUsername1, samplePassword1);
        console.log("Failed: useInvite doesn't reject for database error.");
    } catch (e) {
        console.log("Passed: useInvite rejects for database error.");
    }

    //CREATE tables for next tests
    /*
    await auth.db.aRun("CREATE TABLE auth (username STRING, salt STRING, key STRING, inviteAllowed INTEGER)");
    await auth.db.aRun("CREATE TABLE invites (issuer STRING, code STRING)");
    await auth.db.aRun("CREATE TABLE sessions (username STRING, token STRING, timestamp INTEGER)");
    */
    auth.init();

    //Make a sample request for password authentication. Fails because auth database is currently empty.
    req = { body: { password: samplePassword1, username: sampleUsername1 } }
    res = new SampleResponse(function (data) {
        if (this.code === 0) throw ".end called before .status, check auth.js for errors.";
        else if (this.code === 200) console.log("Failed: authenticatePassword request to empty database with no password validated as correct.");
        else if (this.code === 403) console.log("Passed: authenticatePassword request to empty database rejected as no valid password-user pair exists.");
        else if (this.code === 401) console.log("Failed: authenticatePassword request to empty database rejected on false grounds of there being no password or username in the body.");
        else throw "Unexpected status code, not 0, 200, 403, or 401";
    });
    await auth.authenticatePassword(req, res);


    //Make another sample request, this time with failing body data. Do this for three 401 states, and a sample 403.
    req1 = { body: { username: sampleUsername1 } }
    req2 = { body: { password: samplePassword1 } }
    req3 = { body: {} }
    req4 = { body: { username: sampleUsername2, password: samplePassword2 } }
    res401 = new SampleResponse(function (data) {
        if (this.code === 0) throw ".end called before .status, check auth.js for errors.";
        else if (this.code === 200) console.log("Failed: authenticatePassword request returns valid status despite invalid body data.");
        else if (this.code === 403) console.log("Failed: authenticatePassword request returns 403 where a 401 should do.");
        else if (this.code === 401) console.log("Passed: authenticatePassword request returns 401 where body does not contain required data.");
        else throw "Unexpected status code, not 0, 200, 403, or 401";
    });
    res403 = new SampleResponse(function (data) {
        if (this.code === 0) throw ".end called before .status, check auth.js for errors.";
        else if (this.code === 200) console.log("Failed: authenticatePassword request returns 200 where body has nonexistent credentials.");
        else if (this.code === 403) console.log("Passed: authenticatePassword request returns 403 where body has nonexistent credentials.");
        else if (this.code === 401) console.log("Failed: authenticatePassword request returns 401 where credentials were supplied.");
        else throw "Unexpected status code, not 0, 200, 403, or 401";
    });
    await auth.authenticatePassword(req1, res401);
    res401.status(0);
    await auth.authenticatePassword(req2, res401);
    res401.status(0);
    await auth.authenticatePassword(req3, res401);
    await auth.authenticatePassword(req4, res403);

    //Call signup without sufficient data.
    signupReq1 = { body: { password: samplePassword1, username: sampleUsername1, inviteCode: undefined } }
    signupReq2 = { body: { password: samplePassword1, username: undefined, inviteCode: "abc123" } }
    signupReq3 = { body: { password: undefined, username: sampleUsername1, inviteCode: undefined } }
    signupRes = new SampleResponse(function (message) {
        if (this.code === 0) throw "Error: .end called before .status, check auth.js for errors.";
        if (this.code === 200) console.log("Failed: User signed up where body does not contain required data.");
        else if (this.code === 400) console.log("Passed: User signup rejected with 400 since body does not contain required data.");
        else throw "Unexpected status code: " + this.code;
    });
    await auth.signup(signupReq1, signupRes);
    signupRes.status(0);
    await auth.signup(signupReq2, signupRes);
    signupRes.status(0);
    await auth.signup(signupReq3, signupRes);

    //Call signup with invalid credentials. Either a password which is >100 chars, a username which is >30 chars, a password which contains special characters, or am inviteCode that isn't in the invite database
    signupReq1 = { body: { password: samplePassword1, username: sampleUsername1, inviteCode: "notvalid" } } //The inviteCode is guaranteed to be invalid because all inviteCodes are in hexadecimal
    signupReq2 = { body: { password: "abc\x0Aabc", username: sampleUsername1, inviteCode: "abc123" } } //The password has a special control character (LF) in it.
    signupReq3 = { body: { password: "a" + ("12345").repeat(20), username: sampleUsername1, inviteCode: "abc123" } } //The password is too long (101 chars).
    signupReq4 = { body: { password: samplePassword1, username: "a" + ("12345").repeat(6), inviteCode: "abc123" } } //The username is too long (31 chars).
    signupRes = new SampleResponse(function (message) {
        if (this.code === 0) throw "Error: .end called before .status, check auth.js for errors.";
        if (this.code === 200) console.log("Failed: User signed up despite " + this.invalidMessage);
        else if (this.code === 400) console.log("Passed: User signup rejected with 400 due to " + this.invalidMessage);
        else throw "Unexpected status code: " + this.code;
    });
    signupRes.invalidMessage = "the inviteCode being invalid.";
    await auth.signup(signupReq1, signupRes);
    signupRes.invalidMessage = "the password containing a special control character.";
    await auth.signup(signupReq2, signupRes);
    signupRes.invalidMessage = "the password being too long.";
    await auth.signup(signupReq3, signupRes);
    signupRes.invalidMessage = "the username being too long.";
    await auth.signup(signupReq4, signupRes);

    //Call signup to create a user-key-salt triple from the user-password pair. Override conventional inviteCode requirement. Check that authenticatePassword works afterwards.
    signupReq = {
        body: { password: samplePassword1, username: sampleUsername1 },
        overrideInviteCode: true
    }
    signupRes = new SampleResponse(function (message) {
        if (this.code === 0) throw "Error: .end called before .status, check auth.js for errors.";
        if (this.code === 200) console.log("Passed: User signed up with inviteOverride set to true.");
        else if (this.code === 400) console.log("Failed: User signup rejected with 400 despite inviteOverride being set to true.");
        else throw "Unexpected status code: " + this.code;
    });
    passwordReq = {
        body: { password: samplePassword1, username: sampleUsername1 },
    }
    passwordRes = new SampleResponse(function (token) {
        if (this.code === 0) throw "Error: .end called before .status, check auth.js for errors.";
        else if (this.code === 200) {
            console.log("Passed: authenticatePassword request validates a correct password-user pair.");
            sessionReq.cookies.sessionToken = token;
        } else if (this.code === 403) console.log("Failed: authenticatePassword request rejected despite there being a correct password-user pair.");
        else if (this.code === 401) console.log("Failed: authenticatePassword request rejected on false grounds of there being no password or username in the body.");
        else throw "Unexpected status code: " + this.code;
    });
    sessionReq = { cookies: { username: sampleUsername1 } }
    sessionRes = new SampleResponse(function (isSession) {
        if (this.code === 0) throw "Error: .end called before .status, check auth.js for errors.";
        else if (this.code === 200) console.log("Passed: authenticateSession request validates a correct token-user pair.");
        else if (this.code === 403) console.log("Failed: authenticateSession request rejected despite there being a correct token-user pair.");
        else if (this.code === 401) console.log("Failed: authenticateSession request rejected on false grounds of there being no sessionToken or username in the body.");
        else throw "Unexpected status code: " + this.code;
    });
    await auth.signup(signupReq, signupRes);
    var passwordAuthenticated = await auth.authenticatePassword(passwordReq, passwordRes); //The passwordReq.end callback will automatically assign the new token to the sessionReq.body object

    var sessionAuthenticated = await auth.authenticateSession(sessionReq, sessionRes, () => {}); //Do the same for sessionAuthenticated.
    if (sessionAuthenticated) console.log("Passed: sessionAuthenticated returns true with the createUser() token and username.");
    else console.log("Failed: sessionAuthenticated returns false with the createUser() token and username.");

    var isSession = await auth.isSession(sampleUsername1, sessionReq.cookies.sessionToken); //Now that a sampleToken is established, run isSession with valid data.
    if (isSession) console.log("Passed: isSession returns true with the createUser() token and username.");
    else console.log("Failed: isSession returns false with the createUser() token and username.");

    //Issue an invite using auth.issueInvite and the previous user's credentials. Should fail because previous user lacks the permissions.
    var inviteCode = await auth.issueInvite(sampleUsername1, samplePassword1);
    if (inviteCode !== undefined) console.log("Failed: inviteCode created where user should lack the permissions to do so.");
    else console.log("Passed: inviteCode was not created because user lacked the permissions to do so.");

    //Change user permissions, then issue an invite using auth.issueInvite and the previous user's credentials. Should now succeed.
    await auth.db.aRun("UPDATE auth SET inviteAllowed=1 WHERE username=$username", { //Make the first sampleUser able to invite users.
        $username: sampleUsername1
    });
    var inviteCode = await auth.issueInvite(sampleUsername1, samplePassword1);
    if (inviteCode !== undefined) console.log("Passed: inviteCode created where user has the permissions to do so.");
    else console.log("Failed: inviteCode was not created where user should have the permissions to do so.");

    //Test the creation of a user with new credentials and an inviteCode from the previous user, without using overrideInviteCode.
    signupReq = {
        body: { password: samplePassword1, username: sampleUsername1, inviteCode: inviteCode },
        overrideInviteCode: false
    }
    signupRes = new SampleResponse(function (token) {
        if (this.code === 0) throw "Error: .end called before .status, check auth.js for errors.";
        else if (this.code === 200) console.log("Passed: signup succeeded when using the newly allocated inviteCode.");
        else if (this.code === 400) console.log("Failed: signup failed despite having valid new inviteCode.");
        else throw "Unexpected status code: " + this.code;
    });
    

})().catch((err) => {
    console.log("Error in test syntax, please locate and correct.");
    throw err;
});
