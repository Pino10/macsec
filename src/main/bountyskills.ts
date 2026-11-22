/**
 * Review methods for bug bounty style work, for the AI report on web, API and mobile checks.
 * They sit beside the shared security skills: the AI is told to prove before it reports, to rate
 * by demonstrated impact, to skip what a default scanner and everyone else will already have
 * found, and to write the report so that triage has little to downgrade.
 */
import { skillText } from './seckit/skills'

export const BOUNTY_SKILLS: Record<string, string> = {
  'verify-with-proof': `# Verify with proof

Nothing is a finding until it was seen to work. For each item:
- Keep the exact request and answer that show it (secrets and other people's data hidden).
- Keep a control: the same request done by someone who is allowed, and by someone who is refused, so the difference is clear.
- Name the rule that was broken in one sentence, and the business effect in plain words.
- Check a change by reading the object back as its owner, not only from the answer to the change.
- Reject it when: it only works on your own object; the answer is 200 but empty or an error; it needs an action the program rules out; it is only a version banner or a known-CVE match with no working proof.
Mark each item verified, partly verified (say what is missing), or rejected (say why).`,
  'hypotheses-from-invariants': `# Hypotheses from broken rules

A bug is a way to break a rule that must always hold. For this app, write the rules, then the ways to break them:
- A user can only read or change what belongs to their own account or organisation.
- Prices, discounts and balances are worked out on the server and cannot go negative.
- A step cannot run before the one before it is done.
- A one-time code, coupon or credit works once.
- A privileged action needs a privileged role on every route, every method and every API version.
- A check of an email or phone is tied to the account and to the action it protects.
Then compare every way the same data or action can be reached (web, mobile API, v1 and v2, single item and list, export, preview, webhook, admin). Any difference in who may do what is a lead. For every route, try: no sign-in; another account's object; a low role on an admin function; extra fields such as role or balance; odd numbers; a repeat and a burst.
Prefer ideas specific to this app's own features. A plain "change the id" on a simple page is usually already reported. Look for two weak findings that chain into one strong one.`,
  'novelty-and-impact': `# Novelty and impact

Spend human time on what is unlikely to be a duplicate and matters. For each lead ask: is the asset new or recently changed; could a default scanner or a public checklist find it (then it is low value); does it depend on this app's own workflow (then it is high value); does it chain with another finding into takeover, money loss or data exposure (report the chain); what is the effect in business terms. Send on: high novelty with real impact. Hold and try to deepen: middling. Drop unless critical: generic and low impact. Never report a known-CVE match without proof on the target, or something the programme lists as out of scope.`,
  'bounty-report-writing': `# Writing the report so triage has little to downgrade

Make the first screen decide it. Use: a title that says which feature lets which attacker do what; severity and weakness; two or three sentences of summary; the accounts and roles used; numbered steps a stranger could follow in five minutes, with the control and the actual result; the proof of impact, saying testing stopped there; the business impact in concrete terms; the root cause and fix; any chain.
Severity: rate by what was demonstrated. Triage downgrades for preconditions ("needs the victim logged in", "needs a secret", "third-party host", "out of scope"), so answer them in the report: say which apply, and show the variant that removes one if it exists. Say what the attacker must know and prove it can be learned: a public identifier is very different from a secret. State the blast radius (how many accounts, whether the victim is told). Offer to retest after a fix. Argue impact and reliability, not CVSS letters.
Style: plain words, short sentences, no hype. One issue per report unless it is one chain. Never include other people's real data.`
}

/** The text of review methods by name: the shared skills and the bounty ones. */
export function methodText(names: string[]): string {
  return names.map((n) => (BOUNTY_SKILLS[n] ?? skillText([n]))).filter(Boolean).join('\n\n---\n\n')
}
