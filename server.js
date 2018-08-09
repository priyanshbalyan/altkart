'use strict';

const express = require('express');
const session = require('express-session');
const path = require('path');
const app = express();
const bodyParser = require('body-parser');
const mainRouter = require('./routes/main');
const otpRouter = require('./routes/otp');
const Config = require('./config');

app.use('/css', express.static('static/css'));
app.use('/js', express.static('static/js'));
app.use('/img', express.static('static/img'));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.set('views', path.join(__dirname, 'views/pages'));
app.set('view engine', 'ejs');

app.use(session({
    secret: Config.SESSION_KEY,
    saveUninitialized: true,
    resave: false
}));

app.use((req, res, next) => {
    if (!req.session.messages)
        req.session.messages = [];
    res.locals.removeMessages = function() {
        req.session.messages = [];
        res.locals.messages = [];
    }
    if (req.session.messages)
        res.locals.messages = req.session.messages;

    next();
});

app.use('/', mainRouter);
app.use('/2fa', otpRouter);

app.get('*', (req, res, next) => {
    console.error("404 Error", req.originalUrl);
});

app.use((error, req, res, next) => {
    console.error("500 Error", error);
});

app.listen(Config.PORT || 5000, Config.HOST || "0.0.0.0", () => {
    console.log('listening on ' + (Config.HOST || "0.0.0.0") + ": " + (Config.PORT || 5000));
});