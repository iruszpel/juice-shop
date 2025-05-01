/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import config from 'config'
import PDFDocument from 'pdfkit'
import { type Request, type Response, type NextFunction } from 'express'
import { z } from 'zod'

import { challenges, products } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { BasketItemModel } from '../models/basketitem'
import { DeliveryModel } from '../models/delivery'
import { QuantityModel } from '../models/quantity'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'
import { WalletModel } from '../models/wallet'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'
import * as db from '../data/mongodb'

// Define validation schemas
const orderDetailsSchema = z.object({
  deliveryMethodId: z.number().int().positive().optional(),
  paymentId: z.string().max(50).optional(),
  addressId: z.number().int().positive().optional()
})

const placeOrderSchema = z.object({
  UserId: z.number().int().positive().optional(),
  orderDetails: orderDetailsSchema.optional(),
  couponData: z.string().max(200).optional()
})

interface Product {
  quantity: number
  id?: number
  name: string
  price: number
  total: number
  bonus: number
}

// Authentication middleware
function authenticate (req: Request, res: Response, next: NextFunction) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '')

  if (!token) {
    return res.status(401).json({ message: 'Authentication required' })
  }

  const loggedInUser = security.authenticatedUsers.get(token)
  if (!loggedInUser?.data?.id) {
    return res.status(401).json({ message: 'Invalid authentication token' })
  }

  // Add user info to request for authorization checks
  req.user = { id: loggedInUser.data.id, email: loggedInUser.data.email }
  next()
}

export function placeOrder () {
  return [
    authenticate,
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        // Validate URL parameter
        const basketId = z.string().parse(req.params.id)

        // Validate request body
        const validatedBody = placeOrderSchema.parse(req.body)

        // Check user authorization if UserId is provided
        if (validatedBody.UserId && req.user?.id !== validatedBody.UserId) {
          return res.status(403).json({ message: 'Access denied: Cannot place an order for another user' })
        }

        // Find basket with products
        const basket = await BasketModel.findOne({
          where: { id: basketId },
          include: [{ model: ProductModel, paranoid: false, as: 'Products' }]
        })

        if (!basket) {
          return res.status(404).json({ message: `Basket with id=${basketId} does not exist.` })
        }

        // Verify the basket belongs to the user
        if (basket.UserId !== req.user?.id) {
          return res.status(403).json({ message: 'Access denied: This basket belongs to another user' })
        }
        const email = req.user?.email || ''
        // Use a cryptographically strong random identifier along with the hash
        const orderId = security.hash(email).slice(0, 4) + '-' + utils.randomHexString(16)

        // Create a safe filename with random elements to prevent predictability
        const safeOrderId = orderId.replace(/[^a-zA-Z0-9-_]/g, '_')
        const pdfFile = `order_${safeOrderId}.pdf`
        const pdfPath = path.join('ftp/', pdfFile)

        // Ensure the target directory exists and is writable
        if (!fs.existsSync('ftp/')) {
          fs.mkdirSync('ftp/', { recursive: true })
        }

        const doc = new PDFDocument({ margin: 50 })
        const fileWriter = doc.pipe(fs.createWriteStream(pdfPath))

        fileWriter.on('finish', async () => {
          try {
            // Clear the basket after order is completed
            await basket.update({ coupon: null })
            await BasketItemModel.destroy({ where: { BasketId: basketId } })
            return res.json({ orderConfirmation: orderId })
          } catch (error) {
            next(error)
          }
        })

        fileWriter.on('error', (error) => {
          next(new Error(`Failed to generate order confirmation: ${error.message}`))
        })

        // Generate PDF content
        doc.font('Times-Roman').fontSize(40).text(config.get<string>('application.name'), { align: 'center' })
        doc.moveTo(70, 115).lineTo(540, 115).stroke()
        doc.moveTo(70, 120).lineTo(540, 120).stroke()
        doc.fontSize(20).moveDown()
        doc.font('Times-Roman').fontSize(20).text(req.__('Order Confirmation'), { align: 'center' })
        doc.fontSize(20).moveDown()
        doc.font('Times-Roman').fontSize(15).text(`${req.__('Customer')}: ${email}`, { align: 'left' })
        doc.font('Times-Roman').fontSize(15).text(`${req.__('Order')} #: ${orderId}`, { align: 'left' })
        doc.moveDown()

        const date = new Date().toJSON().slice(0, 10)
        doc.font('Times-Roman').fontSize(15).text(`${req.__('Date')}: ${date}`, { align: 'left' })
        doc.moveDown()
        doc.moveDown()

        // Process order items
        let totalPrice = 0
        const basketProducts: Product[] = []
        let totalPoints = 0

        for (const product of basket.Products ?? []) {
          if (product.BasketItem) {
            // For CTF
            challengeUtils.solveIf(challenges.christmasSpecialChallenge,
              () => product.BasketItem?.ProductId === products.christmasSpecial.id
            )

            // Update product quantity in inventory (with proper error handling)
            try {
              const productQuantity = await QuantityModel.findOne({
                where: { ProductId: product.BasketItem?.ProductId }
              })

              if (productQuantity) {
                const newQuantity = Math.max(0, productQuantity.quantity - product.BasketItem.quantity)
                await QuantityModel.update(
                  { quantity: newQuantity },
                  { where: { ProductId: product.BasketItem?.ProductId } }
                )
              }
            } catch (error) {
              console.error(`Failed to update quantity for product ${product.BasketItem.ProductId}:`, error)
            }

            // Calculate price based on user status
            let itemPrice: number
            if (security.isDeluxe(req)) {
              itemPrice = product.deluxePrice
            } else {
              itemPrice = product.price
            }

            const itemTotal = itemPrice * product.BasketItem.quantity
            const itemBonus = Math.round(itemPrice / 10) * product.BasketItem.quantity

            // Create product entry for order record
            const productEntry = {
              quantity: product.BasketItem.quantity,
              id: product.id,
              name: req.__(product.name),
              price: itemPrice,
              total: itemTotal,
              bonus: itemBonus
            }

            basketProducts.push(productEntry)

            // Add to PDF
            doc.text(`${product.BasketItem.quantity}x ${req.__(product.name)} ${req.__('ea.')} ${itemPrice} = ${itemTotal}¤`)
            doc.moveDown()

            totalPrice += itemTotal
            totalPoints += itemBonus
          }
        }

        doc.moveDown()

        // Apply discount if applicable
        const discount = calculateApplicableDiscount(basket, req) ?? 0
        let discountAmount = '0'
        if (discount > 0) {
          discountAmount = (totalPrice * (discount / 100)).toFixed(2)
          doc.text(`${discount}% discount from coupon: -${discountAmount}¤`)
          doc.moveDown()
          totalPrice -= parseFloat(discountAmount)
        }

        // Add delivery method
        const deliveryMethod = {
          deluxePrice: 0,
          price: 0,
          eta: 5
        }

        if (validatedBody.orderDetails?.deliveryMethodId) {
          const deliveryMethodFromModel = await DeliveryModel.findOne({
            where: { id: validatedBody.orderDetails.deliveryMethodId }
          })

          if (deliveryMethodFromModel) {
            deliveryMethod.deluxePrice = deliveryMethodFromModel.deluxePrice
            deliveryMethod.price = deliveryMethodFromModel.price
            deliveryMethod.eta = deliveryMethodFromModel.eta
          }
        }

        const deliveryAmount = security.isDeluxe(req) ? deliveryMethod.deluxePrice : deliveryMethod.price
        totalPrice += deliveryAmount

        doc.text(`${req.__('Delivery Price')}: ${deliveryAmount.toFixed(2)}¤`)
        doc.moveDown()
        doc.font('Helvetica-Bold').fontSize(20).text(`${req.__('Total Price')}: ${totalPrice.toFixed(2)}¤`)
        doc.moveDown()
        doc.font('Helvetica-Bold').fontSize(15).text(`${req.__('Bonus Points Earned')}: ${totalPoints}`)
        doc.font('Times-Roman').fontSize(15).text(`(${req.__('The bonus points from this order will be added 1:1 to your wallet ¤-fund for future purchases!')}`)
        doc.moveDown()
        doc.moveDown()
        doc.font('Times-Roman').fontSize(15).text(req.__('Thank you for your order!'))

        // For CTF
        challengeUtils.solveIf(challenges.negativeOrderChallenge, () => totalPrice < 0)

        // Process payment and update wallet
        if (validatedBody.UserId) {
          if (validatedBody.orderDetails && validatedBody.orderDetails.paymentId === 'wallet') {
            try {
              const wallet = await WalletModel.findOne({ where: { UserId: validatedBody.UserId } })

              if (wallet && wallet.balance >= totalPrice) {
                await WalletModel.decrement(
                  { balance: totalPrice },
                  { where: { UserId: validatedBody.UserId } }
                )
              } else {
                next(new Error('Insufficient wallet balance.')); return
              }
            } catch (error) {
              next(error); return
            }
          }

          try {
            // Add bonus points to wallet
            await WalletModel.increment(
              { balance: totalPoints },
              { where: { UserId: validatedBody.UserId } }
            )
          } catch (error) {
            console.error('Failed to add bonus points to wallet:', error)
          }
        }

        // Store order in database
        try {
          await db.ordersCollection.insert({
            promotionalAmount: discountAmount,
            paymentId: validatedBody.orderDetails ? validatedBody.orderDetails.paymentId : null,
            addressId: validatedBody.orderDetails ? validatedBody.orderDetails.addressId : null,
            orderId,
            delivered: false,
            email: (email ? email.replace(/[aeiou]/gi, '*') : undefined),
            totalPrice,
            products: basketProducts,
            bonus: totalPoints,
            deliveryPrice: deliveryAmount,
            eta: deliveryMethod.eta.toString()
          })

          // Finalize PDF document
          doc.end()
        } catch (error) {
          next(new Error(`Failed to store order: ${(error as any).message}`))
        }
      } catch (error) {
        if (error instanceof z.ZodError) {
          return res.status(400).json({ message: 'Invalid input data', details: error.errors })
        }
        next(error)
      }
    }
  ]
}

function calculateApplicableDiscount (basket: BasketModel, req: Request) {
  // Check for coupon in basket
  if (security.discountFromCoupon(basket.coupon ?? undefined)) {
    const discount = security.discountFromCoupon(basket.coupon ?? undefined)

    // For CTF
    challengeUtils.solveIf(challenges.forgedCouponChallenge, () => discount ?? 0 >= 80)

    return discount
  // eslint-disable-next-line @typescript-eslint/brace-style
  }
  // Check for coupon in request body
  else if (req.body.couponData) {
    try {
      const couponData = Buffer.from(req.body.couponData, 'base64').toString().split('-')

      if (couponData.length !== 2) {
        return 0
      }

      const couponCode = couponData[0]
      const couponDate = Number(couponData[1])

      // Validate coupon format
      if (isNaN(couponDate) || couponDate <= 0) {
        return 0
      }

      const campaign = campaigns[couponCode as keyof typeof campaigns]

      if (campaign && couponDate === campaign.validOn) {
        // For CTF
        challengeUtils.solveIf(challenges.manipulateClockChallenge, () => campaign.validOn < new Date().getTime())

        return campaign.discount
      }
    } catch (error) {
      console.error('Error processing coupon data:', error)
    }
  }
  return 0
}

const campaigns = {
  WMNSDY2019: { validOn: new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime(), discount: 75 },
  WMNSDY2020: { validOn: new Date('Mar 08, 2020 00:00:00 GMT+0100').getTime(), discount: 60 },
  WMNSDY2021: { validOn: new Date('Mar 08, 2021 00:00:00 GMT+0100').getTime(), discount: 60 },
  WMNSDY2022: { validOn: new Date('Mar 08, 2022 00:00:00 GMT+0100').getTime(), discount: 60 },
  WMNSDY2023: { validOn: new Date('Mar 08, 2023 00:00:00 GMT+0100').getTime(), discount: 60 },
  ORANGE2020: { validOn: new Date('May 04, 2020 00:00:00 GMT+0100').getTime(), discount: 50 },
  ORANGE2021: { validOn: new Date('May 04, 2021 00:00:00 GMT+0100').getTime(), discount: 40 },
  ORANGE2022: { validOn: new Date('May 04, 2022 00:00:00 GMT+0100').getTime(), discount: 40 },
  ORANGE2023: { validOn: new Date('May 04, 2023 00:00:00 GMT+0100').getTime(), discount: 40 }
}
