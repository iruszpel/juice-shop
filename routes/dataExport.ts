/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { z } from 'zod'

import * as challengeUtils from '../lib/challengeUtils'
import { MemoryModel } from '../models/memory'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// Define validation schema for data export
const dataExportSchema = z.object({
  UserId: z.number().int().positive()
})

export function dataExport () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate request token and extract logged in user
      const token = req.headers?.authorization?.replace('Bearer ', '')
      if (!token) {
        return res.status(401).json({ message: 'Authentication required' })
      }

      const loggedInUser = security.authenticatedUsers.get(token)
      if (!loggedInUser?.data?.email || !loggedInUser.data.id) {
        return res.status(401).json({ message: 'Invalid authentication token' })
      }

      // Validate request body
      const validatedData = dataExportSchema.parse(req.body)

      // Check if user is requesting their own data (authorization check)
      if (validatedData.UserId !== loggedInUser.data.id) {
        return res.status(403).json({ message: 'Access denied: Cannot access another user\'s data' })
      }

      const username = loggedInUser.data.username
      const email = loggedInUser.data.email
      const updatedEmail = email.replace(/[aeiou]/gi, '*')

      // Define structured data object with typed properties
      const userData = {
        username,
        email,
        orders: [] as Array<{
          orderId: string
          totalPrice: number
          products: Array<{ productId: string, quantity: number }>
          bonus: number
          eta: string
        }>,
        reviews: [] as Array<{
          message: string
          author: string
          productId: string
          likesCount: number
          likedBy: string[]
        }>,
        memories: [] as Array<{
          imageUrl: string
          caption: string
        }>
      }

      try {
        // Get memories with proper error handling
        const memories = await MemoryModel.findAll({
          where: { UserId: validatedData.UserId },
          attributes: ['imagePath', 'caption'] // Only select needed fields
        })

        memories.forEach((memory: MemoryModel) => {
          userData.memories.push({
            imageUrl: `${req.protocol}://${req.get('host')}/${memory.imagePath}`,
            caption: memory.caption
          })
        })

        // Get orders with proper error handling and avoid callback hell with async/await
        const orders = await db.ordersCollection.find({ email: updatedEmail }).toArray()

        if (orders && orders.length > 0) {
          orders.forEach((order: any) => {
            userData.orders.push({
              orderId: order.orderId,
              totalPrice: order.totalPrice,
              products: [...order.products],
              bonus: order.bonus,
              eta: order.eta
            })
          })
        }

        // Get reviews with proper error handling
        const reviews = await db.reviewsCollection.find({ author: email }).toArray()

        if (reviews && reviews.length > 0) {
          reviews.forEach((review: any) => {
            userData.reviews.push({
              message: review.message,
              author: review.author,
              productId: review.product,
              likesCount: review.likesCount,
              likedBy: review.likedBy
            })
          })
        }

        // Challenge checks
        const emailHash = security.hash(email).slice(0, 4)
        for (const order of userData.orders) {
          challengeUtils.solveIf(challenges.dataExportChallenge,
            () => order.orderId.split('-')[0] !== emailHash
          )
        }

        return res.status(200).json({
          userData: JSON.stringify(userData, null, 2),
          confirmation: 'Your data export will open in a new Browser window.'
        })
      } catch (error) {
        next(new Error(`Error retrieving user data: ${(error as any).message}`))
      }
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: 'Invalid input data', details: error.errors })
      }
      next(error)
    }
  }
}
