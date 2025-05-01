import { type Request, type Response, type NextFunction } from 'express'
import { z } from 'zod'
import validator from 'validator'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import { WalletModel } from '../models/wallet'
// import { SecurityQuestionModel } from '../models/securityQuestion'
// import { SecurityAnswerModel } from '../models/securityAnswer'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import config from 'config'

// Define validation schema for user registration
const userRegistrationSchema = z.object({
  email: z.string().email().max(100).refine(
    (email) => validator.isEmail(email, { allow_utf8_local_part: false }),
    { message: 'Invalid email format' }
  ),
  password: z.string().min(8).max(100),
  passwordRepeat: z.string().min(8).max(100),
  securityQuestion: z.object({
    id: z.number().int().positive()
  }).optional(),
  securityAnswer: z.string().max(100).optional()
}).refine(data => data.password === data.passwordRepeat, {
  message: "Passwords don't match",
  path: ['passwordRepeat']
})

/**
 * Handles user registration with proper validation and security measures
 */
export function registerUser () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate input
      const validatedData = userRegistrationSchema.parse(req.body)

      // Check if email is already registered
      const existingUser = await UserModel.findOne({ where: { email: validatedData.email } })
      if (existingUser) {
        return res.status(400).json({
          status: 'error',
          message: 'Email already exists'
        })
      }

      // Create user with securely hashed password (avoiding MD5/weak hashing)
      console.log('registerUser validatedData', validatedData)
      console.log('hashed password', security.hash(validatedData.password))
      const user = await UserModel.create({
        email: validatedData.email,
        password: validatedData.password,
        role: 'customer',
        deluxeToken: '',
        totpSecret: '',
        isActive: true
      })

      // Create wallet for user
      await WalletModel.create({ UserId: user.id, balance: 0 })

      //   // If security question was provided, save it
      //   if (validatedData.securityQuestion && validatedData.securityAnswer) {
      //     // Verify security question exists
      //     const securityQuestion = await SecurityQuestionModel.findByPk(validatedData.securityQuestion.id)
      //     if (!securityQuestion) {
      //       return res.status(400).json({
      //         status: 'error',
      //         message: 'Security question not found'
      //       })
      //     }

      //     // Save security answer
      //     await SecurityAnswerModel.create({
      //       UserId: user.id,
      //       SecurityQuestionId: validatedData.securityQuestion.id,
      //       answer: security.hash(validatedData.securityAnswer)
      //     })
      //   }

      // Check for CTF challenges
      challengeUtils.solveIf(challenges.registerAdminChallenge, () => {
        return validatedData.email === 'admin@juice-sh.op' || validatedData.email === 'admin@' + config.get<string>('application.domain')
      })

      // Return success response with limited user data (no sensitive info)
      return res.status(201).json({
        status: 'success',
        data: {
          id: user.id,
          email: user.email,
          role: user.role
        }
      })
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          status: 'error',
          message: 'Invalid input data',
          details: error.errors
        })
      }
      next(error)
    }
  }
}

/**
 * For CTF challenges
 */
export function registerAdminChallenge () {
  return (req: Request, res: Response, next: NextFunction) => {
    challengeUtils.solveIf(challenges.registerAdminChallenge, () => {
      return req.body.email === 'admin@juice-sh.op' || req.body.email === 'admin@' + config.get<string>('application.domain')
    })
    next()
  }
}

/**
 * For CTF challenges
 */
export function passwordRepeatChallenge () {
  return (req: Request, res: Response, next: NextFunction) => {
    challengeUtils.solveIf(challenges.passwordRepeatChallenge, () => {
      return req.body.password && req.body.passwordRepeat && req.body.password !== req.body.passwordRepeat
    })
    next()
  }
}

/**
 * For CTF challenges
 */
export function emptyUserRegistration () {
  return (req: Request, res: Response, next: NextFunction) => {
    challengeUtils.solveIf(challenges.emptyUserRegistration, () => {
      return req.body && (!req.body.email || req.body.email === '') && (!req.body.password || req.body.password === '')
    })
    next()
  }
}
