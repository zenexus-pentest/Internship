import models = require('../models/index')
import { Request, Response, NextFunction } from 'express'
import { User } from '../data/types'
import { BasketModel } from '../models/basket'
import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')
import config from 'config'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'
import bcrypt from 'bcrypt'  // Import bcrypt for password hashing
import jwt from 'jsonwebtoken' // Import jsonwebtoken

const security = require('../lib/insecurity')
const users = require('../data/datacache').users

module.exports = function login () {
  function afterLogin(user: { data: User, bid: number }, res: Response, next: NextFunction) {
    verifyPostLoginChallenges(user) // Check for post login challenges
    BasketModel.findOrCreate({ where: { UserId: user.data.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        // Generate JWT token after successful authentication
        const token = jwt.sign(
          { id: user.data.id, email: user.data.email, role: user.data.role },
          'your-secret-key', // Replace with a secret key stored in an environment variable
          { expiresIn: '1h' } // Set the token to expire in 1 hour
        )

        user.bid = basket.id // Keep track of original basket
        security.authenticatedUsers.put(token, user)
        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
      })
      .catch((error: Error) => {
        next(error)
      })
  }

  return (req: Request, res: Response, next: NextFunction) => {
    verifyPreLoginChallenges(req) // Check for pre-login challenges

    // Query the database for the user with the provided email and password
    models.sequelize.query(
      `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND deletedAt IS NULL`, 
      { model: UserModel, plain: true }
    )
    .then(async (authenticatedUser) => {
      const user = utils.queryResultToJson(authenticatedUser)

      // Check if the password is correct using bcrypt
      const isPasswordValid = await bcrypt.compare(req.body.password, user.data.password)

      if (isPasswordValid) {
        // Handle the case when TOTP (two-factor authentication) is required
        if (user.data?.id && user.data.totpSecret !== '') {
          return res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: security.authorize({
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          })
        }

        // If credentials are valid, log in the user and issue a JWT token
        afterLogin(user, res, next)

      } else {
        res.status(401).send(res.__('Invalid email or password.'))
      }
    })
    .catch((error: Error) => {
      next(error)
    })
  }

  // Pre-login challenge checks
  function verifyPreLoginChallenges(req: Request) {
    challengeUtils.solveIf(challenges.weakPasswordChallenge, () => {
      return req.body.email === 'admin@' + config.get<string>('application.domain') && req.body.password === 'admin123'
    })
    // Add more challenges as needed...
  }

  // Post-login challenge checks
  function verifyPostLoginChallenges(user: { data: User }) {
    challengeUtils.solveIf(challenges.loginAdminChallenge, () => { return user.data.id === users.admin.id })
    challengeUtils.solveIf(challenges.loginJimChallenge, () => { return user.data.id === users.jim.id })
    challengeUtils.solveIf(challenges.loginBenderChallenge, () => { return user.data.id === users.bender.id })
    challengeUtils.solveIf(challenges.ghostLoginChallenge, () => { return user.data.id === users.chris.id })
  }
}
