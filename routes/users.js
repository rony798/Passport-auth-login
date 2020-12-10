const express = require('express');
const { route } = require('.');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

//User model
const User = require('../models/User');


//Login Page
router.get('/login', (req, res) =>  res.render('login'));

//Register Page
router.get('/register', (req, res) => res.render('register'));

//Register Handler
router.post('/register', (req, res) => {
    const {name, email, password, password2} = req.body;
    let errors = [];

    //Check Required fields
    if(!name || !email || !password || !password2) {
        errors.push( {msg : 'Please fill all the required details.'});
    }

    //Check password matches
    if(password2 !== password) {
        errors.push({msg : 'Password does not match.'});
    }

    //Check is password lenth is atleast 6 characters
    if(password.length < 6) {
        errors.push({msg : 'password should be atleast 6 characters'});
    }

    if(errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    }
    else {
        //Validation passed
        User.findOne({ email : email})
            .then(user => {
                if(user) {
                    //User exists
                    errors.push({ msg : 'Email is already registered'});
                    res.render('register', {
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });
                }
                else {
                    const newUser = new User({ 
                        name,
                        email,
                        password 
                    });
                    
                    //Hash Password
                    bcrypt.genSalt(10, (err, salt) => 
                        bcrypt.hash(newUser.password, salt,  (err, hash) => {
                            if(err) throw err;
                            // Set password to Hash
                            newUser.password = hash;

                            //Save user 
                            newUser.save()
                                .then(user => {
                                    req.flash('success_msg','You are now registered and can login');
                                    res.redirect('/users/login');
                                })
                                .catch(err => console.log(err));
                    }))
                }
            });
    }

});

// Login Handle
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect : '/dashboard',
        failureRedirect : '/users/login',
        failureFlash : true
    })(req, res, next);
});


//Logout Handle
router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg' , 'You got logged out'); 
    res.redirect('/users/login');
})


module.exports = router;
