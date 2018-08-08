'use strict';
const express = require('express');
let mainRouter = express.Router();
const fs = require('fs');
const validator = require('email-validator');
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
            return res.redirect('/otpneeded');
    }
    next();
}

mainRouter.get('/otpneeded', isAuthenticated, (req, res, next) => {
    res.render('otp', { message: "" });
});

mainRouter.post('/otpneeded', (req, res, next) => {
    let verify = req.body.verify;
    let found = db.users.find(x => x.email == req.session.user);
    let isValid = otplib.authenticator.check(verify, found.otp_key);
    console.log(isValid, req.body);
    if (isValid) {
        req.session.otp = true;
        return res.redirect('/dashboard');
    }
    return res.redirect('/otpneeded');
});

mainRouter.get('/', (req, res, next) => {
    res.render('index', { message: "" });
});

mainRouter.post('/login', (req, res, next) => {
    //console.log(req.body);
    let found = db.users.find(x => x.email == req.body.login_email);
    if (found)
        if (found.password == req.body.login_password) {
            req.session.user = found.email;
            req.session.fullname = found.fullname;
            req.session.isAuthenticated = true;
            if (found.otp_enabled)
                req.session.otp_key = found.otp_key
            return res.redirect('/dashboard');
        }
    return res.redirect('/');
});

mainRouter.post('/signup', (req, res, next) => {
    console.log(req.body);
    if (req.body.password != req.body.confirm_password)
        return res.render('index', { message: "Passwords don't match." });
    if (!validator.validate(req.body.email))
        return res.render('index', { message: "E-mail is not valid. Please type a valid E-mail" });
    db.users.push({ email: req.body.email, password: req.body.password, fullname: req.body.fullname, otp: false });
    req.session.user = req.body.email;
    req.session.fullname = req.body.fullname;
    updateDB();
    res.redirect('/dashboard');
});

mainRouter.get('/dashboard', isAuthenticated, otpenabled, (req, res, next) => {
    res.render('dashboard', { message: "" });
});

mainRouter.get('/about', (req, res, next) => {
    res.render('about', { message: "" });
});

mainRouter.get('/contactus', (req, res, next) => {
    res.render('contact', { message: "" });
});

mainRouter.get('/privacy', (req, res, next) => {
    res.render('privacy', { message: "" });
});

mainRouter.get('/logout', (req, res, next) => {
    req.session.user = null;
    req.session.fullname = null;
    req.session.isAuthenticated = false
    req.session.otp = null;
    res.redirect('/');
});

mainRouter.post('/2fa', isAuthenticated, (req, res, next) => {
    if (!req.session.fullname || !req.session.user) return res.send({ success: false, error: "Invalid credentials" });
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

mainRouter.post('/verify2fa', isAuthenticated, (req, res, next) => {
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

mainRouter.post('/disable2fa', isAuthenticated, otpenabled, (req, res, next) => {
    console.log(req.body);
    let isValid = otplib.authenticator.check(req.body.disableotp, req.session.otp_key);
    if (isValid) {
        let found = db.users.find(x => x.email == req.session.user);
        found.otp_enabled = false;
        updateDB();
        console.log("2fa disabled");
        return res.redirect('/dashboard') //2fa disabled;
    }
    return res.send("otp invalid");
});

function updateDB() {
    fs.writeFile("./db.json", JSON.stringify(db, null, 4), err => {
        if (err) console.log(err);
    });
}

module.exports = mainRouter;