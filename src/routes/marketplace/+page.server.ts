import DatabaseManager from '$lib/server/db'
import type { PageServerLoad } from './$types'

export const ssr = false

export const load = (async ({ locals }) => {
  return {
    nft: {
      abi: locals.server.marketplace.nft.abi,
      address: locals.server.marketplace.nft.address,
      collection: await locals.server.marketplace.fetchNFTMetadata(DatabaseManager.getAllNFTs())
    },
    marketplace: {
      abi: locals.server.marketplace.abi,
      address: locals.server.marketplace.address
    }
  }
}) satisfies PageServerLoad
