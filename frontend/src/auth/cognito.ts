import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  SignUpCommand,
  ConfirmSignUpCommand,
} from '@aws-sdk/client-cognito-identity-provider'
import { User } from './types'

export interface AuthTokens {
  idToken: string
  refreshToken?: string
  expiresIn?: number
}

function getCognitoConfig() {
  const region = import.meta.env.VITE_COGNITO_REGION || 'ap-south-1'
  const clientId = import.meta.env.VITE_COGNITO_CLIENT_ID || ''
  return { region, clientId }
}

let cognitoClient: CognitoIdentityProviderClient | null = null

export function getCognitoClient(): CognitoIdentityProviderClient {
  if (!cognitoClient) {
    const { region } = getCognitoConfig()
    cognitoClient = new CognitoIdentityProviderClient({ region })
  }
  return cognitoClient
}

/**
 * Decode JWT claims without storing or logging token text.
 */
export function parseJwtClaims(token: string): any {
  try {
    const parts = token.split('.')
    if (parts.length < 2) return null
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const decoded = atob(base64)
    return JSON.parse(decoded)
  } catch {
    return null
  }
}

/**
 * Extract strongly-typed User object from Cognito ID token claims.
 */
export function userFromIdToken(idToken: string): User | null {
  const claims = parseJwtClaims(idToken)
  if (!claims) return null

  // Support both custom claims and Cognito standard claims
  const tenantId =
    claims['custom:tenant_id'] ||
    claims.tenant_id ||
    'default'

  let roles: string[] = []
  if (claims['custom:roles']) {
    roles = String(claims['custom:roles'])
      .split(',')
      .map((r) => r.trim())
      .filter(Boolean)
  } else if (claims['cognito:groups']) {
    roles = Array.isArray(claims['cognito:groups'])
      ? claims['cognito:groups']
      : [String(claims['cognito:groups'])]
  } else if (claims['custom:role']) {
    roles = [String(claims['custom:role'])]
  } else if (claims.role) {
    roles = [String(claims.role)]
  } else {
    roles = ['employee']
  }

  const primaryRole = roles[0] || 'employee'
  const email = claims.email || claims['cognito:username'] || 'user@example.com'
  const sub = claims.sub || claims.user_id || 'usr-unknown'

  return {
    email,
    tenant_id: tenantId,
    roles,
    role: primaryRole,
    sub,
  }
}

/**
 * Perform USER_PASSWORD_AUTH using the AWS SDK Cognito client.
 * Tokens and passwords are never logged to console.
 */
export async function authenticateUser(
  username: string,
  password: string
): Promise<AuthTokens> {
  const { clientId } = getCognitoConfig()
  const client = getCognitoClient()

  const command = new InitiateAuthCommand({
    AuthFlow: 'USER_PASSWORD_AUTH',
    ClientId: clientId,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password,
    },
  })

  const response = await client.send(command)
  const result = response.AuthenticationResult

  if (!result || !result.IdToken) {
    throw new Error('Authentication succeeded but no ID token was returned.')
  }

  return {
    idToken: result.IdToken,
    refreshToken: result.RefreshToken,
    expiresIn: result.ExpiresIn,
  }
}

/**
 * Refresh the ID token using the refresh token stored in sessionStorage.
 */
export async function refreshIdToken(refreshToken: string): Promise<AuthTokens> {
  const { clientId } = getCognitoConfig()
  const client = getCognitoClient()

  const command = new InitiateAuthCommand({
    AuthFlow: 'REFRESH_TOKEN_AUTH',
    ClientId: clientId,
    AuthParameters: {
      REFRESH_TOKEN: refreshToken,
    },
  })

  const response = await client.send(command)
  const result = response.AuthenticationResult

  if (!result || !result.IdToken) {
    throw new Error('Token refresh succeeded but no ID token was returned.')
  }

  return {
    idToken: result.IdToken,
    refreshToken: result.RefreshToken || refreshToken,
    expiresIn: result.ExpiresIn,
  }
}

/**
 * Register a new user in Cognito with email, password, and tenant_id.
 */
export async function signUpUser(
  email: string,
  password: string,
  tenantId: string
): Promise<{ userConfirmed: boolean; userSub: string }> {
  const { clientId } = getCognitoConfig()
  const client = getCognitoClient()

  const command = new SignUpCommand({
    ClientId: clientId,
    Username: email,
    Password: password,
    UserAttributes: [
      { Name: 'email', Value: email },
      { Name: 'custom:tenant_id', Value: tenantId },
    ],
  })

  const response = await client.send(command)
  return {
    userConfirmed: !!response.UserConfirmed,
    userSub: response.UserSub || '',
  }
}

/**
 * Confirm user registration via email confirmation code.
 */
export async function confirmSignUpUser(
  email: string,
  confirmationCode: string
): Promise<void> {
  const { clientId } = getCognitoConfig()
  const client = getCognitoClient()

  const command = new ConfirmSignUpCommand({
    ClientId: clientId,
    Username: email,
    ConfirmationCode: confirmationCode,
  })

  await client.send(command)
}
