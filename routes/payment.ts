/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { z } from 'zod'
import { CardModel } from '../models/card'
import * as security from '../lib/insecurity'

// Define validation schemas
const userIdSchema = z.object({
  UserId: z.number().int().positive()
})

const cardIdParamSchema = z.object({
  id: z.string().transform((val) => parseInt(val, 10)).refine((val) => !isNaN(val) && val > 0, {
    message: 'Card ID must be a positive integer'
  })
})

interface displayCard {
  UserId: number
  id: number
  fullName: string
  cardNum: string
  expMonth: number
  expYear: number
}

// Authentication middleware
function authenticate (req: Request, res: Response, next: NextFunction) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '')

  if (!token) {
    return res.status(401).json({ status: 'error', message: 'Authentication required' })
  }

  const loggedInUser = security.authenticatedUsers.get(token)
  if (!loggedInUser?.data?.id) {
    return res.status(401).json({ status: 'error', message: 'Invalid authentication token' })
  }

  // Add user info to request for authorization checks
  req.user = { id: loggedInUser.data.id }
  next()
}

export function getPaymentMethods () {
  return [
    authenticate,
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        // Validate request body
        const { UserId } = userIdSchema.parse(req.body)

        // Verify user is accessing their own data (authorization)
        if (req.user?.id !== UserId) {
          return res.status(403).json({ status: 'error', message: 'Access denied: Cannot access another user\'s payment methods' })
        }

        const displayableCards: displayCard[] = []
        const cards = await CardModel.findAll({ where: { UserId } })

        cards.forEach(card => {
          const displayableCard: displayCard = {
            UserId: card.UserId,
            id: card.id,
            fullName: card.fullName,
            cardNum: '',
            expMonth: card.expMonth,
            expYear: card.expYear
          }

          // Mask card number for security
          const cardNumber = String(card.cardNum)
          displayableCard.cardNum = '*'.repeat(12) + cardNumber.substring(cardNumber.length - 4)
          displayableCards.push(displayableCard)
        })

        return res.status(200).json({ status: 'success', data: displayableCards })
      } catch (error) {
        if (error instanceof z.ZodError) {
          return res.status(400).json({ status: 'error', message: 'Invalid input data', details: error.errors })
        }
        next(error)
      }
    }
  ]
}

export function getPaymentMethodById () {
  return [
    authenticate,
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        // Validate request params and body
        const { id } = cardIdParamSchema.parse(req.params)
        const { UserId } = userIdSchema.parse(req.body)

        // Verify user is accessing their own data (authorization)
        if (req.user?.id !== UserId) {
          return res.status(403).json({ status: 'error', message: 'Access denied: Cannot access another user\'s payment methods' })
        }

        // Query with validated parameters
        const card = await CardModel.findOne({ where: { id, UserId } })

        if (!card) {
          return res.status(404).json({ status: 'error', message: 'Card not found' })
        }

        const displayableCard: displayCard = {
          UserId: card.UserId,
          id: card.id,
          fullName: card.fullName,
          expMonth: card.expMonth,
          expYear: card.expYear,
          cardNum: ''
        }

        // Mask card number for security
        const cardNumber = String(card.cardNum)
        displayableCard.cardNum = '*'.repeat(12) + cardNumber.substring(cardNumber.length - 4)

        return res.status(200).json({ status: 'success', data: displayableCard })
      } catch (error) {
        if (error instanceof z.ZodError) {
          return res.status(400).json({ status: 'error', message: 'Invalid input data', details: error.errors })
        }
        next(error)
      }
    }
  ]
}

export function delPaymentMethodById () {
  return [
    authenticate,
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        // Validate request params and body
        const { id } = cardIdParamSchema.parse(req.params)
        const { UserId } = userIdSchema.parse(req.body)

        // Verify user is accessing their own data (authorization)
        if (req.user?.id !== UserId) {
          return res.status(403).json({ status: 'error', message: 'Access denied: Cannot delete another user\'s payment methods' })
        }

        // Delete with validated parameters
        const result = await CardModel.destroy({ where: { id, UserId } })

        if (result > 0) {
          return res.status(200).json({ status: 'success', message: 'Card deleted successfully' })
        } else {
          return res.status(404).json({ status: 'error', message: 'Card not found' })
        }
      } catch (error) {
        if (error instanceof z.ZodError) {
          return res.status(400).json({ status: 'error', message: 'Invalid input data', details: error.errors })
        }
        next(error)
      }
    }
  ]
}
