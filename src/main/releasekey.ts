/**
 * The public half of the key that signs MacSec releases. The private half is a GitHub Actions
 * secret, so a release cannot be published without it. A download whose checksum list is not
 * signed by this key is never installed.
 */
export const RELEASE_PUBKEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADqPeBfqn55AfHFSJfb1Cnetd/XOmPHt1pEtxYcIV53w=
-----END PUBLIC KEY-----`
