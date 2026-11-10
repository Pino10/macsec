/**
 * The servers to check, from what the person typed: names, IP addresses, a range such as
 * 192.168.1.10-20 or a small network such as 192.168.1.0/28. One per line or separated by commas.
 * Nothing here touches the network. The list is capped so a typing mistake cannot become a sweep
 * of a whole company network.
 */

export const MAX_TARGETS = 64

const NAME = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$/
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

const octets = (m: RegExpExecArray): number[] => m.slice(1, 5).map(Number)
const ok4 = (o: number[]): boolean => o.length === 4 && o.every((n) => n >= 0 && n <= 255)

export class TargetError extends Error {}

/** Every address in 10.0.0.0/28 style, without the network and broadcast addresses of /30 and larger. */
function cidr(ip: string, bits: number): string[] {
  const m = IPV4.exec(ip)
  const o = m ? octets(m) : []
  if (!ok4(o) || !Number.isInteger(bits) || bits < 0 || bits > 32) throw new TargetError(`“${ip}/${bits}” is not a network.`)
  if (bits < 24) throw new TargetError(`“${ip}/${bits}” is bigger than 254 addresses. Check a /24 or smaller at a time.`)
  const base = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0
  const size = 2 ** (32 - bits)
  const start = base - (base % size)
  const out: string[] = []
  for (let i = 0; i < size; i++) {
    if (bits < 31 && (i === 0 || i === size - 1)) continue
    const n = (start + i) >>> 0
    out.push([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'))
  }
  return out
}

export function expandTargets(input: string, max = MAX_TARGETS): string[] {
  const tokens = input.toLowerCase().split(/[\s,;]+/).map((t) => t.replace(/^[a-z]+:\/\//, '').replace(/\/(?!\d+$).*$/, '').trim()).filter(Boolean)
  if (!tokens.length) throw new TargetError('Enter at least one server name or IP address.')
  const out: string[] = []
  const add = (h: string): void => {
    if (!out.includes(h)) out.push(h)
    if (out.length > max) throw new TargetError(`That is more than ${max} servers. Check them in smaller groups.`)
  }
  for (const t of tokens) {
    if (t.startsWith('-') || t.length > 253) throw new TargetError(`“${t.slice(0, 40)}” is not a server name or address.`)
    const net = /^([\d.]+)\/(\d+)$/.exec(t)
    const range = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$/.exec(t)
    if (net) for (const a of cidr(net[1], Number(net[2]))) add(a)
    else if (range) {
      const [from, to] = [Number(range[2]), Number(range[3])]
      if (!ok4([...range[1].split('.').filter(Boolean).map(Number), from]) || to > 255 || to < from) throw new TargetError(`“${t}” is not a range of addresses.`)
      for (let i = from; i <= to; i++) add(`${range[1]}${i}`)
    } else if (IPV4.test(t)) {
      if (!ok4(octets(IPV4.exec(t)!))) throw new TargetError(`“${t}” is not an IP address.`)
      add(t)
    } else if (NAME.test(t)) add(t)
    else throw new TargetError(`“${t.slice(0, 40)}” is not a server name or address.`)
  }
  return out
}

/** Private network addresses and local names: servers on your own network. */
export const isPrivateTarget = (h: string): boolean => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(h) || /^(localhost|::1)$/.test(h) || /\.(test|localhost|local|lan|internal)$/.test(h)
