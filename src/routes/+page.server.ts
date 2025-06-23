import type { PageServerLoad } from './$types'

export const load = (({ locals }) => {
  return {
    token: locals.server.marketplace.currency.address
    // serverStarted: !!locals.server.signer,
    // accounts: structuredClone(locals.server.accounts)
  }
}) satisfies PageServerLoad
