/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import yaml from 'js-yaml'
import libxml from 'libxmljs'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'
import { z } from 'zod'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

// List of allowed file types
const ALLOWED_FILE_TYPES = ['pdf', 'xml', 'zip', 'yml', 'yaml']
const MAX_FILE_SIZE = 200000 // 200KB

// File validation schema
const fileValidationSchema = z.object({
  originalname: z.string().min(1).max(200),
  mimetype: z.string().min(1).max(100),
  size: z.number().int().positive().max(MAX_FILE_SIZE)
})

function ensureFileIsPassed (req: Request, res: Response, next: NextFunction) {
  if (req.file != null) {
    try {
      // Validate file basic properties
      fileValidationSchema.parse(req.file)
      next()
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'Invalid file',
          details: error.errors
        })
      }
      next(error)
    }
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

function handleZipFileUpload (req: Request, res: Response, next: NextFunction) {
  const file = req.file
  if (!file) {
    next(); return
  }

  if (utils.endsWith(file.originalname.toLowerCase(), '.zip')) {
    if (file.buffer != null && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      const buffer = file.buffer
      const filename = file.originalname.toLowerCase()

      // Create a safe temp file with a randomized name
      const tempFile = path.join(os.tmpdir(), `${Date.now()}-${Math.random().toString(36).substring(2)}-${filename}`)

      try {
        // Create an uploads directory if it doesn't exist
        const uploadsDir = path.resolve('uploads/complaints')
        if (!fs.existsSync(uploadsDir)) {
          fs.mkdirSync(uploadsDir, { recursive: true })
        }

        // Write to temp file
        fs.writeFileSync(tempFile, buffer)

        // Define a safe extraction function to prevent path traversal
        fs.createReadStream(tempFile)
          .pipe(unzipper.Parse())
          .on('entry', function (entry: any) {
            const fileName = path.basename(entry.path) // Only use the basename to prevent path traversal
            const targetPath = path.join(uploadsDir, fileName)

            // Validate the target path is within the complaints directory
            const resolvedPath = path.resolve(targetPath)
            if (!resolvedPath.startsWith(uploadsDir)) {
              entry.autodrain()
              return
            }

            // For CTF/challenge purposes
            challengeUtils.solveIf(challenges.fileWriteChallenge, () => {
              return entry.path === 'legal.md' && resolvedPath === path.resolve('ftp/legal.md')
            })

            // Safe file writing
            entry.pipe(fs.createWriteStream(targetPath)
              .on('error', function (err) {
                console.error('Error writing file:', err)
              })
            )
          })
          .on('error', function (err: unknown) {
            console.error('Error processing zip:', err)
          })
          .on('close', function () {
            // Clean up temp file
            try {
              fs.unlinkSync(tempFile)
            } catch (err) {
              console.error('Error deleting temp file:', err)
            }
          })
      } catch (err) {
        console.error('Error handling zip file:', err)
        next(err); return
      }
    }
    return res.status(204).end()
  } else {
    next()
  }
}

function checkUploadSize (req: Request, res: Response, next: NextFunction) {
  const file = req.file
  if (file != null) {
    // Cap file size to prevent DoS
    if (file.size > MAX_FILE_SIZE) {
      challengeUtils.solveIf(challenges.uploadSizeChallenge, () => true)
      return res.status(413).json({ error: 'File too large' })
    }

    challengeUtils.solveIf(challenges.uploadSizeChallenge, () => file.size > 100000)
  }
  next()
}

function checkFileType (req: Request, res: Response, next: NextFunction) {
  const file = req.file
  if (file != null) {
    const fileExtension = file.originalname
      .substr(file.originalname.lastIndexOf('.') + 1)
      .toLowerCase()

    if (!ALLOWED_FILE_TYPES.includes(fileExtension)) {
      challengeUtils.solveIf(challenges.uploadTypeChallenge, () => true)
      return res.status(415).json({
        error: 'Invalid file type',
        message: 'Only PDF, XML, ZIP, YML, and YAML files are allowed'
      })
    }

    challengeUtils.solveIf(challenges.uploadTypeChallenge, () => {
      return !ALLOWED_FILE_TYPES.includes(fileExtension)
    })
  }
  next()
}

function handleXmlUpload (req: Request, res: Response, next: NextFunction) {
  const file = req.file
  if (!file) {
    next(); return
  }

  if (utils.endsWith(file.originalname.toLowerCase(), '.xml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => true)

    if (file.buffer != null && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      try {
        const data = file.buffer.toString()

        // Safely parse XML with disabled external entity processing to prevent XXE attacks
        const xmlDoc = libxml.parseXml(data, {
          noblanks: true,
          noent: false, // Disable entity expansion
          nocdata: true,
          // dtdload: false, // Don't load external DTDs
          dtdvalid: false // Don't validate with DTDs
        })

        const xmlString = xmlDoc.toString(false)

        // For CTF challenge purposes
        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => {
          return utils.matchesEtcPasswdFile(data) || utils.matchesSystemIniFile(data)
        })

        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' +
          utils.trunc(xmlString, 400) + ' (' + file.originalname + ')')); return
      } catch (err: any) {
        // For CTF challenge purposes
        if (utils.contains(err.message, 'Script execution timed out')) {
          challengeUtils.solveIf(challenges.xxeDosChallenge, () => true)
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.')); return
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' +
            err.message + ' (' + file.originalname + ')')); return
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' +
        file.originalname + ')')); return
    }
  }
  next()
}

function handleYamlUpload (req: Request, res: Response, next: NextFunction) {
  const file = req.file
  if (!file) {
    next(); return
  }

  if (utils.endsWith(file.originalname.toLowerCase(), '.yml') ||
      utils.endsWith(file.originalname.toLowerCase(), '.yaml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => true)

    if (file.buffer != null && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      try {
        const data = file.buffer.toString()

        // Parse YAML safely with a size limit and schema validation to prevent YAML bombs
        const parsedYaml = yaml.load(data, {
          schema: yaml.DEFAULT_SAFE_SCHEMA, // Use safe schema to prevent code execution
          json: true // Force JSON compatible output
        })

        const yamlString = JSON.stringify(parsedYaml)

        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' +
          utils.trunc(yamlString, 400) + ' (' + file.originalname + ')')); return
      } catch (err: any) {
        // For CTF challenge purposes
        if (utils.contains(err.message, 'Invalid string length') ||
            utils.contains(err.message, 'Script execution timed out')) {
          challengeUtils.solveIf(challenges.yamlBombChallenge, () => true)
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.')); return
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' +
            err.message + ' (' + file.originalname + ')')); return
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' +
        file.originalname + ')')); return
    }
  }
  return res.status(204).end()
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
}
