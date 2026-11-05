/**
 * "I leaked a key": what to do, in order, for the kind of key a scanner found. Used on secret
 * findings. MacSec never stores the key itself (only its kind, file and line), so these steps
 * never need it either.
 */

export interface LeakGuide {
  id: string
  /** The provider, in words. */
  name: string
  /** Where the key is revoked or rotated. */
  revokeUrl: string
  /** The steps at the provider, in order. */
  steps: string[]
  /** Where to look for use of the key by someone else. */
  logs?: string
}

const GUIDES: (LeakGuide & { match: RegExp })[] = [
  {
    id: 'aws',
    name: 'AWS',
    match: /\baws\b|amazon|akia/i,
    revokeUrl: 'https://console.aws.amazon.com/iam/home#/security_credentials',
    steps: ['In IAM, find the access key (it starts with AKIA or ASIA) and make it inactive.', 'Create a new key for the same user or role, and put it where the app reads it.', 'Delete the old key once nothing uses it.'],
    logs: 'Check CloudTrail for calls made with the old key, and the Billing page for spending you do not recognise.'
  },
  {
    id: 'github',
    name: 'GitHub',
    match: /github|\bghp_|\bgho_|\bghs_|github[-_ ]?pat/i,
    revokeUrl: 'https://github.com/settings/tokens',
    steps: ['Open Settings, Developer settings, Personal access tokens, and delete the token.', 'If it was an app or OAuth token, revoke it on the app’s page instead.', 'Make a new token with only the permissions it needs, and a date it ends.'],
    logs: 'Your security log (Settings, Archives, Security log) shows what the token was used for.'
  },
  {
    id: 'gitlab',
    name: 'GitLab',
    match: /gitlab|\bglpat-/i,
    revokeUrl: 'https://gitlab.com/-/user_settings/personal_access_tokens',
    steps: ['Revoke the token under Access tokens.', 'Make a new one with the smallest scope and an end date.']
  },
  {
    id: 'stripe',
    name: 'Stripe',
    match: /stripe|\bsk_live|\brk_live/i,
    revokeUrl: 'https://dashboard.stripe.com/apikeys',
    steps: ['On the API keys page, choose Roll key for the leaked key. Stripe gives you a new one.', 'Put the new key in your app. A restricted key with only the access it needs is safer.', 'Let the old key expire now, not later.'],
    logs: 'Developers, Logs shows every request; look for ones you did not make.'
  },
  {
    id: 'google',
    name: 'Google Cloud or Firebase',
    match: /gcp|google|firebase|\baiza/i,
    revokeUrl: 'https://console.cloud.google.com/apis/credentials',
    steps: ['Under APIs and services, Credentials, regenerate or delete the key.', 'Restrict the new key to your app (websites, Android or iOS app) and to the APIs it needs.', 'For a service account key (a JSON file), delete that key on the service account’s Keys tab.'],
    logs: 'Cloud Logging and the Billing reports show unexpected use.'
  },
  {
    id: 'azure',
    name: 'Microsoft Azure',
    match: /azure|microsoft/i,
    revokeUrl: 'https://portal.azure.com/',
    steps: ['Find the resource the key belongs to (storage account, app registration, Cognitive Services) and regenerate its key or delete the client secret.', 'Update the app, then regenerate the second key too if both were in the code.'],
    logs: 'The resource’s Activity log and sign-in logs show who used it.'
  },
  {
    id: 'slack',
    name: 'Slack',
    match: /slack|\bxox[abprs]-/i,
    revokeUrl: 'https://api.slack.com/apps',
    steps: ['Open the app on api.slack.com, then OAuth and Permissions, and choose Revoke or Rotate.', 'For a webhook address, delete the webhook under Incoming Webhooks and make a new one.']
  },
  {
    id: 'openai',
    name: 'OpenAI',
    match: /openai|\bsk-proj-/i,
    revokeUrl: 'https://platform.openai.com/api-keys',
    steps: ['Delete the key on the API keys page.', 'Make a new key in the right project, with only the permissions it needs.'],
    logs: 'The Usage page shows spending; set a monthly limit if you have not.'
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    match: /anthropic|\bsk-ant-/i,
    revokeUrl: 'https://console.anthropic.com/settings/keys',
    steps: ['Delete the key in the Claude Console under API keys.', 'Make a new key and keep it in the Keychain or your secret store.'],
    logs: 'Usage and Cost in the Console show what the key was used for.'
  },
  {
    id: 'twilio',
    name: 'Twilio',
    match: /twilio/i,
    revokeUrl: 'https://console.twilio.com/',
    steps: ['Under Account, API keys and tokens, delete the API key, or rotate the auth token (Request a secondary token, then promote it).']
  },
  {
    id: 'sendgrid',
    name: 'SendGrid',
    match: /[Ss][Ee][Nn][Dd][Gg][Rr][Ii][Dd]|\bSG\./,
    revokeUrl: 'https://app.sendgrid.com/settings/api_keys',
    steps: ['Delete the key under Settings, API Keys, and make a new one with only Mail Send if that is all it needs.'],
    logs: 'Activity shows email sent with it.'
  },
  {
    id: 'database',
    name: 'A database password',
    match: /postgres|mysql|mariadb|mongo|redis|database|connection[-_ ]?string|\bdsn\b/i,
    revokeUrl: '',
    steps: ['Change the database user’s password (or make a new user and drop the old one).', 'Check the database is not open to the internet; allow only the addresses that need it.', 'Update the connection string where the app reads it.'],
    logs: 'The database’s connection log shows logins from addresses you do not know.'
  },
  {
    id: 'private-key',
    name: 'A private key',
    match: /private[-_ ]?key|\bssh\b|\bpem\b|rsa|certificate/i,
    revokeUrl: '',
    steps: ['Treat the key pair as lost: make a new pair.', 'Remove the old public key everywhere it is trusted (servers’ authorized_keys, GitHub deploy keys, certificate authorities).', 'If it signed certificates, revoke them.']
  }
]

const GENERIC: LeakGuide = {
  id: 'generic',
  name: 'The service the key belongs to',
  revokeUrl: '',
  steps: ['Sign in to the service and revoke or delete the key.', 'Make a new one with the least access it needs.', 'Put it in an environment variable, the Keychain or a secret store, not in the code.']
}

/** The guide for a secret finding, from what the scanner called it. */
export function leakGuide(f: { title: string; description?: string }): LeakGuide {
  const text = `${f.title} ${f.description ?? ''}`
  const g = GUIDES.find((x) => x.match.test(text))
  if (!g) return GENERIC
  const { match: _m, ...rest } = g
  return rest
}

/** What to do after the provider step: the same for every key. */
export function afterRevoking(inHistory: boolean): string[] {
  return [
    'Take the key out of the code and read it from an environment variable (.env that is in .gitignore) or a secret store.',
    ...(inHistory
      ? [
          'It is in the Git history, so deleting the line is not enough. Rewrite the history with git filter-repo (brew install git-filter-repo), for example: git filter-repo --replace-text expressions.txt, where the file lists the old key.',
          'Force-push the rewritten branches, and ask everyone with a copy to clone again. Forks and caches may still have it: that is why revoking comes first.'
        ]
      : ['If it was ever pushed or shared, assume it was copied, even if you delete it now.']),
    'Add a check so it does not happen again: a Gitleaks pre-commit hook, or GitHub push protection.'
  ]
}
