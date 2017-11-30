const jwt = require('jwt-simple');

const config = require('../config');
const User = require('../models/user');

function tokenForUser(user) {
    const timestamp = new Date().getTime();
    return jwt.encode({ sub: user.id, iat: timestamp}, config.secret);
}

exports.signin = function(req, res, next) {
    // User jas already had their email and password auth'd
    // We just need to give them a token
    res.send({ token: tokenForUser(req.user)});
};

exports.signup = function(req, res, next) {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(422).send({ error: 'You must provide email and password'});
    }
    
    User.findOne({ email }, (err, existingUser) => {
        if (err) { return next(err) }

        if (existingUser) {
            return res.status(422).send({ error: 'Email is in use'});
        }

        const user = new User({email, password});

        user.save(function (err) {
            if (err) { return next(err); }

            res.json({ token : tokenForUser(user)});
        });
    })
}