module.exports = function () {
  const { validationResult, check } = require('express-validator');
  const express = require('express');
  const app = express();
  const user = require('../models/user');
  const argon2 = require('argon2');
  const jwt = require('jsonwebtoken');

  const loginValidateBody = [
    check('username').notEmpty().withMessage('Username is required'),
    check('password').notEmpty().withMessage('Password is required')
  ];

  app.post('/login', loginValidateBody, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).send({
        success: false,
        error_code: 422,
        error: errors.array()
      });
    }

    const auth_user = await user().findOne({
      where: {
        username: req.body.username
      }
    });

    if (!auth_user) {
      return res.send({
        success: false,
        error_code: 404,
        error_message: 'User not found'
      })
    }

    if (!await argon2.verify(auth_user.password, req.body.password)) {
      return res.send({
        success: false,
        error_code: 401,
        error_message: 'Verify your password'
      })
    }

    const token = jwt.sign({
      user_id: auth_user.user_id
    }, process.env.SECRET, { expiresIn: (parseInt(process.env.EXP) + Date.now()) });

    return res.send({
      success: true,
      status_code: 200,
      data: {
        token
      }
    })
  });

  const signValidateBody = [
    check('username').notEmpty().withMessage('Username is required'),
    check('email')
      .notEmpty()
      .withMessage('Email is required')
      .isEmail()
      .withMessage('Email must be a email'),
    check('password').notEmpty().withMessage('Password is required')
  ];

  app.post('/signin', signValidateBody, (req, res) => { 
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).send({
        success: false,
        error_code: 422,
        error: errors.array()
      });
    }

    argon2.hash(req.body.password).then(hash => {
      req.body.password = hash;
      user().create(req.body).then(model => {
        console.log(model);
        res.send({
          success: true,
          status_code: 200,
          data: model
        })
      }).catch(err => {
        console.log('err', err);
        res.send({
          success: false,
          error_code: 500,
          error_message: 'Internal server error'
        })
      })
    });
  });

  app.post('/authorizate', async (req, res) => {
    const token = req.headers.authorization.split(' ')[1];
    let payload = {};

    try {
      payload = jwt.verify(token, process.env.SECRET);
    } catch (err) {
      console.log('err', err);
      return res.send({
        success: false,
        error_code: 403,
        error_message: 'Invalid token'
      })
    }

    const auth_user = await user().findOne({
      where: {
        user_id: payload.user_id
      },
      attributes: ['user_id', 'username', 'email']
    });

    return res.send({
      success: true,
      status_code: 200,
      data: {
        user: auth_user
      }
    });
  });

  return app;
}
