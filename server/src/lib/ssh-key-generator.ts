import crypto from 'crypto'

export interface GeneratedSshKeyPair {
  name: string
  publicKey: string
  privateKey: string
  fingerprint: string
}

/**
 * Generate an RSA SSH key pair in the same format used by the user SSH key API.
 * The private key is returned to the caller and is never persisted.
 */
export function generateSshKeyPair(): GeneratedSshKeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
  })

  const sshPublicKey = convertRsaPemToOpenSsh(publicKey)
  const keyData = sshPublicKey.split(/\s+/)[1]
  const fingerprint = calculateFingerprint(keyData)
  const randomSuffix = crypto.randomBytes(4).toString('base64url').slice(0, 5)

  return {
    name: `Incudal-${randomSuffix}`,
    publicKey: sshPublicKey,
    privateKey,
    fingerprint
  }
}

function calculateFingerprint(base64KeyData: string): string {
  const keyBuffer = Buffer.from(base64KeyData, 'base64')
  const hash = crypto.createHash('sha256').update(keyBuffer).digest('base64')
  return `SHA256:${hash.replace(/=+$/, '')}`
}

function writeUInt32BE(value: number): Buffer {
  const buffer = Buffer.alloc(4)
  buffer.writeUInt32BE(value, 0)
  return buffer
}

function convertRsaPemToOpenSsh(pemPublicKey: string): string {
  const publicKeyObject = crypto.createPublicKey({
    key: pemPublicKey,
    format: 'pem'
  })
  const jwk = publicKeyObject.export({ format: 'jwk' }) as { n?: string; e?: string }
  if (!jwk.n || !jwk.e) {
    throw new Error('Failed to export RSA public key as JWK')
  }

  const modulus = Buffer.from(jwk.n, 'base64url')
  const exponent = Buffer.from(jwk.e, 'base64url')
  const modulusWithPadding = modulus[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), modulus]) : modulus
  const exponentWithPadding = exponent[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), exponent]) : exponent
  const keyType = Buffer.from('ssh-rsa', 'utf8')

  const blob = Buffer.concat([
    writeUInt32BE(keyType.length),
    keyType,
    writeUInt32BE(exponentWithPadding.length),
    exponentWithPadding,
    writeUInt32BE(modulusWithPadding.length),
    modulusWithPadding
  ])

  return `ssh-rsa ${blob.toString('base64')}`
}
