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

// Define validation schema for redirect
const redirectSchema = z.object({
  to: z.string().url().max(2000)
})

export function performRedirect () {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate input
      const { to: toUrl } = redirectSchema.parse(req.query)

      // Use a more comprehensive allowlist check
      if (security.isRedirectAllowed(toUrl)) {
        // For CTF challenges
        challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => {
          return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' ||
                 toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' ||
                 toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
        })
        challengeUtils.solveIf(challenges.redirectChallenge, () => {
          return isUnintendedRedirect(toUrl)
        })

        // Secure redirect by ensuring it's relative or to a trusted domain
        // Add an additional security layer beyond isRedirectAllowed
        if (isRelativeOrAllowlisted(toUrl)) {
          res.redirect(toUrl)
        } else {
          res.status(403)
          next(new Error('Forbidden redirect destination: ' + toUrl))
        }
      } else {
        res.status(406)
        next(new Error('Unrecognized target URL for redirect: ' + toUrl))
      }
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ message: 'Invalid redirect URL', details: error.errors })
      } else {
        next(error)
      }
    }
  }
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}

function isRelativeOrAllowlisted (url: string): boolean {
  // Check if the URL is relative (starts with /)
  if (url.startsWith('/')) {
    return true
  }

  // Check against allowlist
  for (const allowedUrl of security.redirectAllowlist) {
    try {
      // Parse both URLs to compare domains
      const targetUrl = new URL(url)
      const allowedUrlObj = new URL(allowedUrl)

      if (targetUrl.hostname === allowedUrlObj.hostname) {
        return true
      }
    } catch {
      // Skip invalid URL entries
      continue
    }
  }

  return false
}
