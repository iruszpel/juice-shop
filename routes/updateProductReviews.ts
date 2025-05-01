/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { z } from 'zod' // Added Zod import

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// Define validation schema for review update
const updateReviewSchema = z.object({
  id: z.string().min(1),
  message: z.string().min(1).max(2000)
})

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req) // vuln-code-snippet vuln-line forgedReviewChallenge

    // Check if user is authenticated
    if (!user?.data?.email) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    try {
      // Validate input
      const validatedInput = updateReviewSchema.parse(req.body)

      // Only allow users to update their own reviews
      db.reviewsCollection.update(
        {
          _id: validatedInput.id,
          author: user.data.email // Ensure user can only update their own reviews
        },
        { $set: { message: validatedInput.message } }
        // Removed multi:true option to prevent multiple updates
      ).then(
        (result: { modified: number, original: Array<{ author: any }> }) => {
          challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 }) // vuln-code-snippet hide-line
          challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 }) // vuln-code-snippet hide-line
          res.json(result)
        }, (err: unknown) => {
          res.status(500).json(err)
        })
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ error: 'Invalid input', details: error.errors })
      } else {
        res.status(500).json({ error: 'Unknown error occurred' })
      }
    }
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
