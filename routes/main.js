'use strict';
const express = require('express');
let mainRouter = express.Router();
const fs = require('fs');
const validator = require('email-validator');
const bcrypt = require('bcryptjs');
const otplib = require('otplib');
const qrcode = require('qrcode');

let db = JSON.parse(fs.readFileSync('./db.json'));


function isAuthenticated(req, res, next) {
    if (!req.session.isAuthenticated) {
        res.locals.messages.push(["Login to access this page", "black"]);
        return res.redirect('/');
    }
    next();
}

function otpenabled(req, res, next) {
    if (!req.session.isAuthenticated) return res.redirect('/');
    let found = db.users.find(x => x.email == req.session.user);
    if (found && found.otp_enabled) {
        if (!req.session.otp)
            return res.redirect('/authenticate');
    }
    next();
}

mainRouter.get('/', (req, res, next) => {
    res.render('index');
});

mainRouter.post('/login', (req, res, next) => {
    //console.log(req.body);
    let found = db.users.find(x => x.email == req.body.login_email);
    if (found)
        if (bcrypt.compareSync(req.body.login_password, found.password)) {
            req.session.user = found.email;
            req.session.fullname = found.fullname;
            req.session.isAuthenticated = true;
            if (found.otp_enabled) {
                req.session.otp_key = found.otp_key
                res.locals.messages.push(["Enter 2FA code to verify.", "black"]);
                return res.redirect('/authenticate');
            }
            res.locals.messages.push(["Logged in", "black"]);
            return res.redirect('/dashboard');
        }
    res.locals.messages.push(["Incorrect email or password.", "red"]);
    return res.redirect('/');
});

mainRouter.post('/signup', (req, res, next) => {
    console.log(req.body);
    if (req.body.password != req.body.confirm_password) {
        res.locals.messages.push(["Passwords don't match.", "red"]);
        return res.redirect('/');
    }
    if (!validator.validate(req.body.email)) {
        res.locals.messages.push(["E-mail is not valid. Please type a valid E-mail", "red"]);
        return res.redirect('/');
    }
    db.users.push({
        email: req.body.email,
        password: bcrypt.hashSync(req.body.password, 8),
        fullname: req.body.fullname,
        otp_enabled: false,
        wallet: [],
        deposit_history: []
    });

    req.session.user = req.body.email;
    req.session.fullname = req.body.fullname;
    updateDB();
    res.locals.messages.push(["Successfull signup!", "black"]);
    res.redirect('/dashboard');
});

mainRouter.get('/dashboard', isAuthenticated, otpenabled, (req, res, next) => {
    let found = db.users.find(x => x.email == req.session.user);

    res.render('dashboard', { message: "", data: found });
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

mainRouter.get('/terms', (req, res, next) => {
    res.render('terms', { message: "" });
});

mainRouter.get('/logout', (req, res, next) => {
    req.session.user = null;
    req.session.fullname = null;
    req.session.isAuthenticated = false
    req.session.otp = null;
    res.locals.messages.push(["Logged out", "black"]);
    res.redirect('/');
});

mainRouter.get('/authenticate', isAuthenticated, (req, res, next) => {
    res.render('otp', { message: "" });
});

function updateDB() {
    fs.writeFile("./db.json", JSON.stringify(db, null, 4), err => {
        if (err) console.log(err);
    });
}

module.exports = mainRouter