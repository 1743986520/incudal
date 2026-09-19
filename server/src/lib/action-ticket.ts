import { nanoid } from 'nanoid'
import { sharedConsume, sharedDel, sharedDelPrefix, sharedListKeys, sharedSet } from './shared-state.js'

export type ActionTicketType = 'oauth-bind' | 'terminal'

interface BaseActionTicket {
  type: ActionTicketType
  userId: number
  issuedAt: number
  sessionId?: string
  expiresAt: number
  createdAt: number
}

interface OAuthBindTicket extends BaseActionTicket {
  type: 'oauth-bind'
}

interface TerminalTicket extends BaseActionTicket {
  type: 'terminal'
  instanceId: number
}

type ActionTicket = OAuthBindTicket | TerminalTicket

// 票据走共享状态层（审查项 P2-09）：多副本部署时任一副本签发、任一副本消费。
// session 索引（action-ticket-session:<sessionId>:<token>）用于按会话批量撤销。
const TICKET_TTL_MS = {
  'oauth-bind': 60 * 1000,
  terminal: 60 * 1000
} as const

const TICKET_KEY_PREFIX = 'action-ticket:'
const TICKET_SESSION_INDEX_PREFIX = 'action-ticket-session:'

async function createTicket(ticket: ActionTicket): Promise<string> {
  const token = nanoid(32)
  const ttlMs = Math.max(ticket.expiresAt - Date.now(), 1)
  await sharedSet(`${TICKET_KEY_PREFIX}${token}`, JSON.stringify(ticket), ttlMs)
  if (ticket.sessionId) {
    await sharedSet(`${TICKET_SESSION_INDEX_PREFIX}${ticket.sessionId}:${token}`, '1', ttlMs)
  }
  return token
}

export function generateOAuthBindTicket(
  userId: number,
  issuedAt: number,
  sessionId?: string
): Promise<string> {
  const now = Date.now()
  return createTicket({
    type: 'oauth-bind',
    userId,
    issuedAt,
    sessionId,
    expiresAt: now + TICKET_TTL_MS['oauth-bind'],
    createdAt: now
  })
}

export function generateTerminalAccessTicket(
  userId: number,
  instanceId: number,
  issuedAt: number,
  sessionId?: string
): Promise<string> {
  const now = Date.now()
  return createTicket({
    type: 'terminal',
    userId,
    instanceId,
    issuedAt,
    sessionId,
    expiresAt: now + TICKET_TTL_MS.terminal,
    createdAt: now
  })
}

export interface OAuthBindTicketConsumeResult {
  valid: boolean
  userId?: number
  issuedAt?: number
  sessionId?: string
  error?: string
}

export interface TerminalTicketConsumeResult {
  valid: boolean
  userId?: number
  instanceId?: number
  issuedAt?: number
  sessionId?: string
  error?: string
}

async function consumeTicket(token: string): Promise<{ ticket: ActionTicket | null; error?: string }> {
  // 消费通过共享状态的"读取即删除"完成，重放请求拿不到载荷
  const raw = await sharedConsume(`${TICKET_KEY_PREFIX}${token}`)
  if (!raw) {
    return { ticket: null, error: 'Ticket not found or already used' }
  }

  let ticket: ActionTicket
  try {
    ticket = JSON.parse(raw) as ActionTicket
  } catch {
    return { ticket: null, error: 'Ticket corrupted' }
  }

  if (Date.now() > ticket.expiresAt) {
    return { ticket: null, error: 'Ticket expired' }
  }

  return { ticket }
}

export async function consumeOAuthBindTicket(token: string): Promise<OAuthBindTicketConsumeResult> {
  const { ticket, error } = await consumeTicket(token)
  if (!ticket || ticket.type !== 'oauth-bind') {
    return { valid: false, error: error || 'Ticket not found or already used' }
  }

  return {
    valid: true,
    userId: ticket.userId,
    issuedAt: ticket.issuedAt,
    sessionId: ticket.sessionId
  }
}

export async function consumeTerminalAccessTicket(
  token: string,
  expectedInstanceId?: number
): Promise<TerminalTicketConsumeResult> {
  const { ticket, error } = await consumeTicket(token)
  if (!ticket || ticket.type !== 'terminal') {
    return { valid: false, error: error || 'Ticket not found or already used' }
  }

  if (expectedInstanceId !== undefined && ticket.instanceId !== expectedInstanceId) {
    return { valid: false, error: 'Instance mismatch' }
  }

  return {
    valid: true,
    userId: ticket.userId,
    instanceId: ticket.instanceId,
    issuedAt: ticket.issuedAt,
    sessionId: ticket.sessionId
  }
}

export async function revokeActionTicketsForSession(sessionId: string): Promise<number> {
  const indexPrefix = `${TICKET_SESSION_INDEX_PREFIX}${sessionId}:`
  const indexKeys = await sharedListKeys(indexPrefix)
  for (const indexKey of indexKeys) {
    await sharedDel(`${TICKET_KEY_PREFIX}${indexKey.slice(indexPrefix.length)}`)
  }
  await sharedDelPrefix(indexPrefix)
  return indexKeys.length
}
