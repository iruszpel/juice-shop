/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { z } from 'zod' // Added Zod import

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from 'data/types'
import * as db from '../data/mongodb'
import * as utils from '../lib/utils'

// Blocking sleep function as in native MongoDB
// @ts-expect-error FIXME Type safety broken for global object
global.sleep = (time: number) => {
  // Ensure that users don't accidentally dos their servers for too long
  if (time > 2000) {
    time = 2000
  }
  const stop = new Date().getTime()
  while (new Date().getTime() < stop + time) {
    ;
  }
}

// Define validation schema for product ID
const productIdSchema = z.union([
  z.number().int().positive(),
  z.string().regex(/^\d+$/).transform(val => Number(val))
])

export function showProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Enable the noSqlCommandChallenge, but with safer validation
      let productId
      if (!utils.isChallengeEnabled(challenges.noSqlCommandChallenge)) {
        productId = productIdSchema.parse(req.params.id)
      } else {
        // For challenge purposes, still allow the challenge to be completed
        // but with better input validation
        const truncatedId = utils.trunc(req.params.id, 40)

        // Measure how long the query takes, to check if there was a nosql dos attack
        const t0 = new Date().getTime()

        // Try to parse as a number first
        try {
          productId = productIdSchema.parse(truncatedId)
        } catch (e) {
          // For challenge demonstration - if it contains the sleep command, we'll use it
          // but in a more controlled way
          if (truncatedId.includes('sleep') && utils.isChallengeEnabled(challenges.noSqlCommandChallenge)) {
            db.reviewsCollection.find({ $where: 'this.product == ' + truncatedId }).then((reviews: Review[]) => {
              const t1 = new Date().getTime()
              challengeUtils.solveIf(challenges.noSqlCommandChallenge, () => { return (t1 - t0) > 2000 })
              processReviews(reviews, req, res)
            }, () => {
              res.status(400).json({ error: 'Invalid parameters' })
            })
            return
          } else {
            return res.status(400).json({ error: 'Invalid product ID format' })
          }
        }
      }

      // Use a safe query approach avoiding $where
      db.reviewsCollection.find({ product: productId }).then((reviews: Review[]) => {
        processReviews(reviews, req, res)
      }, () => {
        res.status(400).json({ error: 'Invalid parameters' })
      })
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ error: 'Invalid product ID', details: error.errors })
      } else {
        res.status(500).json({ error: 'An unexpected error occurred' })
      }
    }
  }
}

// Helper function to process reviews and send response
function processReviews (reviews: Review[], req: Request, res: Response) {
  const user = security.authenticatedUsers.from(req)
  for (let i = 0; i < reviews.length; i++) {
    if (user === undefined || reviews[i].likedBy.includes(user.data.email)) {
      reviews[i].liked = true
    }
  }
  res.json(utils.queryResultToJson(reviews))
}
