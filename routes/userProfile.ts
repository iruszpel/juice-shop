/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import pug from 'pug'
import fs from 'node:fs/promises'
import { URL } from 'url'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate authentication token
      const token = req.cookies.token
      if (!token) {
        return res.status(401).json({ message: 'Authentication required' })
      }

      const loggedInUser = security.authenticatedUsers.get(token)
      if (!loggedInUser || !loggedInUser.data.id) {
        return res.status(403).json({ message: 'Invalid authentication token' })
      }

      // Fetch user from database
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        return res.status(404).json({ message: 'User not found' })
      }

      // Read template
      let template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })

      // Sanitize username to prevent SSTI
      let username = user.username

      // For CTF challenge purposes only
      if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
        req.app.locals.abused_ssti_bug = true

        // Record challenge but sanitize output
        if (username && username.includes('<script>alert(`xss`)</script>')) {
          challengeUtils.solve(challenges.usernameXssChallenge)
        }

        // Sanitize the username
        // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
        username = entities.encode(username || '')
      } else {
        // Always sanitize username to prevent XSS
        // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
        username = entities.encode(username || '')
      }

      // Get theme configuration
      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']

      // Safely replace template variables
      template = template.replace(/_username_/g, username)
      template = template.replace(/_emailHash_/g, security.hash(user.email || ''))
      template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
      template = template.replace(/_favicon_/g, favicon())
      template = template.replace(/_bgColor_/g, theme.bgColor)
      template = template.replace(/_textColor_/g, theme.textColor)
      template = template.replace(/_navColor_/g, theme.navColor)
      template = template.replace(/_primLight_/g, theme.primLight)
      template = template.replace(/_primDark_/g, theme.primDark)
      template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

      // Compile template safely
      const fn = pug.compile(template)

      // Set a secure Content-Security-Policy
      // Properly sanitize profile image URL to prevent CSP injection
      let sanitizedProfileImage = ''
      if (user.profileImage) {
        try {
          const url = new URL(user.profileImage)
          // Only allow http and https protocols
          if (url.protocol === 'http:' || url.protocol === 'https:') {
            // Extract just the origin and path to prevent CSP injection
            sanitizedProfileImage = `${url.origin}${url.pathname}`
          }
        } catch (e) {
          // If URL parsing fails, don't include the profile image in CSP
          sanitizedProfileImage = ''
        }
      }

      const CSP = `default-src 'self'; img-src 'self' ${sanitizedProfileImage}; script-src 'self' https://code.getmdl.io https://ajax.googleapis.com; style-src 'self' https://code.getmdl.io https://fonts.googleapis.com 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com`

      // For CTF purposes
      if (username && user.profileImage?.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null &&
          utils.contains(username, '<script>alert(`xss`)</script>')) {
        challengeUtils.solve(challenges.usernameXssChallenge)
      }

      // Set security headers
      res.set({
        'Content-Security-Policy': CSP,
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block'
      })

      res.send(fn(user))
    } catch (error) {
      next(error)
    }
  }
}
