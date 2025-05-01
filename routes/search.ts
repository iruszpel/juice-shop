/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { z } from 'zod'
import { Op } from 'sequelize'

import * as utils from '../lib/utils'
import * as models from '../models/index'
import { UserModel } from '../models/user'
import { ProductModel } from '../models/product'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

class ErrorWithParent extends Error {
  parent: Error | undefined
}

// Define validation schema for search query
const searchSchema = z.object({
  q: z.string().max(200).optional().default('')
})

// vuln-code-snippet start unionSqlInjectionChallenge dbSchemaChallenge
export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate input
      const { q } = searchSchema.parse(req.query)
      const criteria = q === 'undefined' ? '' : q

      // Use Sequelize ORM with parameterized queries instead of raw SQL
      ProductModel.findAll({
        where: {
          [Op.and]: [
            {
              [Op.or]: [
                { name: { [Op.like]: `%${criteria}%` } },
                { description: { [Op.like]: `%${criteria}%` } }
              ]
            },
            { deletedAt: null }
          ]
        },
        order: [['name', 'ASC']]
      })
        .then((products) => {
          const dataString = JSON.stringify(products)

          // Keep challenge checks
          if (challengeUtils.notSolved(challenges.unionSqlInjectionChallenge)) { // vuln-code-snippet hide-start
            let solved = true
            UserModel.findAll().then(data => {
              const users = utils.queryResultToJson(data)
              if (users.data?.length) {
                for (let i = 0; i < users.data.length; i++) {
                  solved = solved && utils.containsOrEscaped(dataString, users.data[i].email) && utils.contains(dataString, users.data[i].password)
                  if (!solved) {
                    break
                  }
                }
                if (solved) {
                  challengeUtils.solve(challenges.unionSqlInjectionChallenge)
                }
              }
            }).catch((error: Error) => {
              next(error)
            })
          }

          if (challengeUtils.notSolved(challenges.dbSchemaChallenge)) {
            let solved = true
            void models.sequelize.query('SELECT sql FROM sqlite_master').then(([data]: any) => {
              const tableDefinitions = utils.queryResultToJson(data)
              if (tableDefinitions.data?.length) {
                for (let i = 0; i < tableDefinitions.data.length; i++) {
                  if (tableDefinitions.data[i].sql) {
                    solved = solved && utils.containsOrEscaped(dataString, tableDefinitions.data[i].sql)
                    if (!solved) {
                      break
                    }
                  }
                }
                if (solved) {
                  challengeUtils.solve(challenges.dbSchemaChallenge)
                }
              }
            })
          } // vuln-code-snippet hide-end

          // Process product translations
          const processedProducts = products.map(product => {
            const productObj = product.toJSON()
            return {
              ...productObj,
              name: req.__(productObj.name),
              description: req.__(productObj.description)
            }
          })

          res.json(utils.queryResultToJson(processedProducts))
        }).catch((error: ErrorWithParent) => {
          next(error.parent)
        })
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ message: 'Invalid search query', details: error.errors })
      } else {
        next(error)
      }
    }
  }
}
// vuln-code-snippet end unionSqlInjectionChallenge dbSchemaChallenge
