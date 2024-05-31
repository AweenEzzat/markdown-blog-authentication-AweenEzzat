const express = require('express');
const bcrypt = require('bcrypt');
const User = require('./../models/user');
const router = express.Router();

// Sign in function
router.post('/signin', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username: username });
    if (!user) {
      return res.status(400).render('user/signin', { error: 'wrong username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).render('user/signin', { error: 'wrong username or password' });
    }

    res.setHeader('user', user.id);
    res.redirect('/user/authenticated');
  } catch (error) {
    res.status(500).send('Server error');
  }
});

// Sign up function
router.post('/signup', async (req, res) => {
  const {
    firstname,
    lastname,
    username,
    password,
    password2,
    acceptTos,
    avatar,
  } = req.body;

  if (password !== password2) {
    return res.status(400).render('user/signup', { error: "passwords don't match" });
  }

  try {
    const existingUser = await User.findOne({ username: username });
    if (existingUser) {
      return res.status(400).render('user/signup', { error: 'username already used' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      username: username,
      firstname: firstname,
      lastname: lastname,
      password_hash: hashedPassword,
      avatar: avatar,
    });

    await newUser.save();
    res.redirect('/user/authenticated');
  } catch (error) {
    res.status(500).send('Server error');
  }
});

// Sign out function (bonus)
router.get('/signout', (req, res) => {
  res.redirect('/user/signin');
});

// renders sign up page
router.get('/signup', (req, res) => {
  res.render('user/signup');
});

// renders sign in page
router.get('/signin', (req, res) => {
  res.render('user/signin');
});

router.get('/authenticated', (req, res) => {
  res.render('user/authenticated');
});

module.exports = router;
