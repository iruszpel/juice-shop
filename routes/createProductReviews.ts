/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { z } from 'zod' // Added Zod import

import * as challengeUtils from '../lib/challengeUtils'
import { reviewsCollection } from '../data/mongodb'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

// Define validation schema for creating reviews
const createReviewSchema = z.object({
  message: z.string().min(1).max(2000),
  author: z.string().min(1).max(100)
})

// Define validation schema for product ID
const productIdSchema = z.union([
  z.number().int().positive(),
  z.string().regex(/^\d+$/).transform(val => Number(val))
])

export function createProductReviews () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)

    try {
      // Validate the product ID from URL params
      const productId = productIdSchema.parse(req.params.id)

      // Validate request body
      const validatedInput = createReviewSchema.parse(req.body)

      // For the forge review challenge
      challengeUtils.solveIf(
        challenges.forgedReviewChallenge,
        () => user?.data?.email !== validatedInput.author
      )

      // Create the review with validated data
      await reviewsCollection.insert({
        product: productId,
        message: validatedInput.message,
        author: validatedInput.author,
        likesCount: 0,
        likedBy: []
      })

      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({
          status: 'error',
          message: 'Input validation failed',
          errors: err.errors
        })
      }
      return res.status(500).json(utils.getErrorMessage(err))
    }
  }
}
