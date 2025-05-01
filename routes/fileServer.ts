/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import { z } from 'zod'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

// Define validation schema for file parameter
const fileParamSchema = z.object({
  file: z.string().max(100).refine(value => !value.includes('/') && !value.includes('\\'), {
    message: 'File names cannot contain path separators'
  })
})

// Define allowlisted file types
// const ALLOWED_FILE_TYPES = ['.md', '.pdf', 'incident-support.kdbx']

export function servePublicFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate file parameter
      const { file } = fileParamSchema.parse(req.params)

      // Sanitize file name and apply additional security measures
      const sanitizedFile = sanitizeFileName(file)

      if (isAllowedFile(sanitizedFile)) {
        // Keep CTF challenges
        challengeUtils.solveIf(challenges.directoryListingChallenge, () => sanitizedFile.toLowerCase() === 'acquisitions.md')
        verifySuccessfulPoisonNullByteExploit(sanitizedFile)

        // Use path.join instead of path.resolve and validate the final path is within the intended directory
        const filePath = path.join('ftp', sanitizedFile)
        const resolvedPath = path.resolve(filePath)

        // Ensure the file is within the ftp directory (prevent path traversal)
        const ftpDir = path.resolve('ftp')
        if (!resolvedPath.startsWith(ftpDir)) {
          res.status(403)
          next(new Error('Access to file outside permitted directory denied')); return
        }

        res.sendFile(resolvedPath)
      } else {
        res.status(403)
        next(new Error('Only .md and .pdf files are allowed!'))
      }
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ message: 'Invalid file parameter', details: error.errors })
      } else {
        next(error)
      }
    }
  }

  function sanitizeFileName (file: string): string {
    // Remove null bytes and other potentially harmful characters
    let sanitized = security.cutOffPoisonNullByte(file)

    // Remove any directory traversal sequences
    sanitized = sanitized.replace(/\.\.\//g, '').replace(/\.\.\\/g, '')

    return sanitized
  }

  function isAllowedFile (file: string): boolean {
    // Check if the file is specifically allowed or has an allowed extension
    return file === 'incident-support.kdbx' ||
           utils.endsWith(file, '.md') ||
           utils.endsWith(file, '.pdf')
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }
}
