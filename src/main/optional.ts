/**
 * Tools that were in the T3MP3ST pack but that MacSec does not install or run, because they
 * attack rather than inspect. They are listed so you know what exists; if you need one for an
 * authorised test, install it yourself from its official site. MacSec only checks whether it is
 * already on this Mac, and never starts it.
 */
import { existsSync } from 'fs'
import type { OptionalTool } from '../shared/types'

const brew = (bin: string): string[] => [`/opt/homebrew/bin/${bin}`, `/usr/local/bin/${bin}`]

const LIST: (Omit<OptionalTool, 'installed'> & { paths: string[] })[] = [
  { name: 'Metasploit Framework', what: 'Exploitation framework. MacSec uses it only when you switch it on for a server check, and only the modules you tick one by one: the own check of Metasploit for a known flaw, or a look-only scanner that reads a version or banner. Never exploit, login or brute force. Install it yourself.', homepage: 'https://www.metasploit.com', paths: [...brew('msfconsole'), '/opt/metasploit-framework/bin/msfconsole'] },
  { name: 'Dalfox', what: 'Finds and confirms cross-site scripting (XSS) by sending payloads.', homepage: 'https://github.com/hahwul/dalfox', paths: brew('dalfox') },
  { name: 'Hydra', what: 'Password guessing against sign-in pages and services.', homepage: 'https://github.com/vanhauser-thc/thc-hydra', paths: brew('hydra') },
  { name: 'hashcat', what: 'Password hash cracking.', homepage: 'https://hashcat.net/hashcat/', paths: brew('hashcat') },
  { name: 'John the Ripper', what: 'Password hash cracking.', homepage: 'https://www.openwall.com/john/', paths: brew('john') },
  { name: 'Pacu', what: 'AWS exploitation framework.', homepage: 'https://github.com/RhinoSecurityLabs/pacu', paths: brew('pacu') },
  { name: 'objection', what: 'Frida-based toolkit for bypassing mobile app protections.', homepage: 'https://github.com/sensepost/objection', paths: brew('objection') },
  { name: 'drozer', what: 'Attacks Android apps through their exported parts.', homepage: 'https://github.com/WithSecureLabs/drozer', paths: brew('drozer') },
  { name: 'garak', what: 'Sends jailbreak and prompt-injection attempts to a language model to see what gets through. Run it yourself, only against your own model (for example in LM Studio).', homepage: 'https://github.com/NVIDIA/garak', paths: brew('garak') },
  { name: 'promptfoo red team', what: 'Attacks an AI app with adversarial prompts to find prompt injection and data leaks. Run it yourself, only against your own app.', homepage: 'https://www.promptfoo.dev/docs/red-team/', paths: brew('promptfoo') },
  { name: 'GDB with pwndbg', what: 'Debugger set up for exploit development.', homepage: 'https://github.com/pwndbg/pwndbg', paths: brew('gdb') }
]

export function optionalTools(): OptionalTool[] {
  return LIST.map(({ paths, ...t }) => ({ ...t, installed: paths.some((p) => existsSync(p)) }))
}
