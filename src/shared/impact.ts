/**
 * Controlled exploitation: proving what someone could actually do, on systems the person is engaged
 * to test. This is the one part of MacSec that changes something or reads real data, so it is built
 * like a contract rather than a feature:
 *
 *   - nothing runs without a written engagement (client, authority, hosts, window, caps, impacts);
 *   - every action says in advance what it sends, what it aims to prove and what it will not do;
 *   - the person approves the plan step by step and types EXPLOIT <host> before it starts;
 *   - the run stops at the first proof of each goal, never at the biggest pile of damage;
 *   - every request is logged with the values hidden, and every write has a cleanup or a leftover.
 *
 * CIA: every step aims at one of confidentiality, integrity or availability, so a report can say
 * which of the three was demonstrated, and which was not.
 */

export type ImpactClass = 'confidentiality' | 'integrity' | 'availability'

export const IMPACT_CLASSES: ImpactClass[] = ['confidentiality', 'integrity', 'availability']

/** The three letters, for the UI and the report. */
export const IMPACT_LETTER: Record<ImpactClass, string> = {
  confidentiality: 'C',
  integrity: 'I',
  availability: 'A'
}

export type ImpactActionId =
  | 'traversal-read'
  | 'ssti-marker'
  | 'upload-write'
  | 'availability-probe'
  | 'replay-request'

export type ImpactMethod = 'GET' | 'POST' | 'PUT' | 'PATCH'

export interface EngagementCaps {
  /** Requests the whole engagement may send through MacSec. */
  requests: number
  /** Requests that can change data. */
  writes: number
  /** Minutes a single campaign may run. */
  minutes: number
}

export interface EngagementDraft {
  client: string
  /** The written authority: a contract or ticket number, an email subject, a programme reference. */
  authorityRef: string
  /** The person, or the body, that gave the authority. */
  authorizedBy: string
  /** Exact hosts, or a leading wildcard (*.example.com). A wildcard never covers the apex. */
  hosts: string[]
  /** Addresses on the local network or this Mac: usually a staging server you control. */
  allowPrivate: boolean
  startsAt: string
  endsAt: string
  caps: EngagementCaps
  /** Which kinds of impact the authority allows. */
  allowed: ImpactClass[]
  notes?: string
}

export interface Engagement extends EngagementDraft {
  id: string
  createdAt: string
  revokedAt?: string
  /** Spent by every run under this engagement so far. */
  used: { requests: number; writes: number }
}

export interface ImpactActionInfo {
  id: ImpactActionId
  name: string
  what: string
  impact: ImpactClass[]
  /** What it sends, in plain words. */
  sends: string
  /** What it never does. */
  never: string
  /** The most requests it can send, ever. */
  maxRequests: number
  writes: boolean
  /** How it undoes its own change, or what it leaves for the person. */
  cleanup: string
  risk: string
  /** What the person has to give it. */
  needs: ('url' | 'param' | 'verifyUrl' | 'request' | 'expect')[]
}

export interface PlannedStep {
  id: string
  action: ImpactActionId
  aims: ImpactClass
  url: string
  /** The parameter or form field the action works on. */
  param?: string
  /** For replay-request: the exact message. */
  method?: ImpactMethod
  headers?: Record<string, string>
  body?: string
  /** For upload-write: where to read the file back, with {name} for the file name. */
  verifyUrl?: string
  /** For replay-request: a string the answer must contain to count as proof. */
  expect?: string
  /** The finding this step chains from. */
  from?: string
  why: string
  /** The exact requests this step will send. Shown before approval. */
  preview: string[]
  /** Step ids that must be proven first. */
  after?: string[]
  /** It can change data: needs write approval and either cleanup or an acknowledged leftover. */
  write?: boolean
  /** How to undo it by hand when it cannot be undone automatically. */
  undo?: string
}

export interface ImpactPlan {
  id: string
  engagementId: string
  target: string
  goal: ImpactClass[]
  steps: PlannedStep[]
  source: 'rules' | 'ai'
  caps: EngagementCaps
  notes: string[]
  at: string
}

export interface ImpactPlanRequest {
  engagementId: string
  target: string
  goal: ImpactClass[]
  /** Ask an AI to pick the steps as well, from the catalogue only. */
  useAi?: boolean
  reviewer?: string
}

export interface ImpactRunRequest {
  planId: string
  /** The exact phrase EXPLOIT <host>. */
  phrase: string
  /** The ids of the steps the person ticked. */
  approved: string[]
  /** Acknowledged that a write step may leave one file behind. */
  acceptLeftovers: boolean
}

export interface ImpactEvidence {
  method: string
  url: string
  status: number
  contentType?: string
  bytes: number
  sha256: string
  at: string
  shows: string[]
}

export interface ImpactStepResult {
  step: string
  action: ImpactActionId
  aims: ImpactClass
  status: 'proven' | 'not-proven' | 'failed' | 'skipped'
  title: string
  detail: string
  evidence?: ImpactEvidence
  ms: number
  cleanup?: { done: boolean; how: string }
}

export interface ImpactLeftover {
  what: string
  where: string
  how: string
}

export interface ImpactRun {
  id: string
  planId: string
  engagementId: string
  target: string
  startedAt: string
  finishedAt: string
  goal: ImpactClass[]
  proven: ImpactClass[]
  steps: ImpactStepResult[]
  leftover: ImpactLeftover[]
  stopped: string
  requests: number
  writes: number
}

/** One line of the audit log: what was sent, with values hidden. */
export interface ImpactAuditEntry {
  at: string
  method: string
  url: string
  requestBytes: number
  status: number
  responseBytes: number
  responseSha: string
  note?: string
}

export interface ImpactProgress {
  runId: string
  step: string
  line: string
}
