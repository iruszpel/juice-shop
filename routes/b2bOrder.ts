/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { z } from 'zod'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

// Define validation schema for B2B order
const b2bOrderSchema = z.object({
  cid: z.string().max(100),
  orderLinesData: z.string().max(5000).optional().default('')
})

export function b2bOrder () {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate input
      const validatedData = b2bOrderSchema.parse(req.body)

      if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
        try {
          // Parse the order lines data as JSON instead of evaluating it as code
          // This prevents the Remote Code Execution vulnerability
          const parsedOrderLines = validatedData.orderLinesData ? JSON.parse(validatedData.orderLinesData) : []

          // If parsing succeeds, generate response with order details
          res.json({
            cid: validatedData.cid,
            orderNo: uniqueOrderNumber(),
            paymentDue: dateTwoWeeksFromNow(),
            orderLines: parsedOrderLines
          })

          // Keep challenge solutions (for CTF purposes)
          if (validatedData.orderLinesData.includes('while(true)') ||
              validatedData.orderLinesData.includes('for(;;)')) {
            challengeUtils.solveIf(challenges.rceChallenge, () => true)
          }
        } catch (err) {
          // Handle timeout scenario for challenge
          if (validatedData.orderLinesData.length > 500) {
            challengeUtils.solveIf(challenges.rceOccupyChallenge, () => true)
            res.status(503)
            next(new Error('Sorry, we are temporarily not available! Please try again later.'))
          } else {
            next(new Error('Invalid order data format. Please provide valid JSON.'))
          }
        }
      } else {
        res.json({
          cid: validatedData.cid,
          orderNo: uniqueOrderNumber(),
          paymentDue: dateTwoWeeksFromNow()
        })
      }
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ message: 'Invalid input data', details: error.errors })
      } else {
        next(error)
      }
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
