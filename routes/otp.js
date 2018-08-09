'use strict';
const express = require('express');
const otpRouter = express.Router();
const fs = require('fs');
const otplib = require('otplib');
const qrcode = require('qrcode');

let db = JSON.parse(fs.readFileSync('./db.json'));

function isAuthenticated(req, res, next) {
    if (!req.session.isAuthenticated) return res.redirect('/');
    next();
}

function otpenabled(req, res, next) {
    if (!req.session.isAuthenticated) return res.redirect('/');
    let found = db.users.find(x => x.email == req.session.user);
    if (found && found.otp_enabled) {
        if (!req.session.otp)
            return res.redirect('/2fa/authenticate');
    }
    next();
}

otpRouter.post('/authenticate', (req, res, next) => {
    let verify = req.body.verify;
    let found = db.users.find(x => x.email == req.session.user);
    let isValid = otplib.authenticator.check(verify, found.otp_key);
    console.log(isValid, req.body);
    if (isValid) {
        req.session.otp = true;
        return res.redirect('/dashboard');
    }
    res.locals.messages.push(["Invalid 2FA code.", "red"]);
    return res.redirect('/2fa/authenticate');
});

otpRouter.post('/enable', isAuthenticated, (req, res, next) => {
    if (!req.session.fullname || !req.session.user)
        return res.send({ success: false, error: "Invalid credentials" });
    let key = otplib.authenticator.generateSecret();
    const otpauth = otplib.authenticator.keyuri(req.session.user, "service", key);
    qrcode.toDataURL(otpauth, (err, imageUrl) => {
        if (err) {
            console.log('Error with QR');
            return res.send({ success: false, error: err });
        }
        req.session.otp_key = key;
        //console.log(imageUrl);
        return res.send({ success: true, image: imageUrl });
    });
});

otpRouter.post('/verify', isAuthenticated, (req, res, next) => {
    let isValid = otplib.authenticator.check(req.body.data, req.session.otp_key);

    if (isValid) {
        let found = db.users.find(x => x.email == req.session.user);
        found.otp_key = req.session.otp_key;
        delete req.session.otp_key;
        found.otp_enabled = true;
        updateDB();
        return res.send({ success: true, message: "Successfully added 2FA" });
    }
    return res.send({ success: false, message: "Not verified" });
});

otpRouter.post('/disable', isAuthenticated, otpenabled, (req, res, next) => {
    console.log(req.body);
    let isValid = otplib.authenticator.check(req.body.disableotp, req.session.otp_key);
    if (isValid) {
        let found = db.users.find(x => x.email == req.session.user);
        found.otp_enabled = false;
        updateDB();
        console.log("2fa disabled");
        res.locals.messages.push(['2FA disabled', "black"]);
        return res.redirect('/dashboard') //2fa disabled;
    }
    res.locals.messages.push(["Incorrect OTP entered.", "black"]);
    return res.redirect('/dashboard');
});

function updateDB() {
    fs.writeFile("./db.json", JSON.stringify(db, null, 4), err => {
        if (err) console.log(err);
    });
}

module.exports = otpRouter;