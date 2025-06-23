import type { Handle } from '@sveltejs/kit'
import { GanacheServer } from '$lib/models/GanacheServer'

let ganacheServer: GanacheServer

export const handle: Handle = async ({ event, resolve }) => {
  if (!ganacheServer) {
    ganacheServer = await GanacheServer.start()
    await ganacheServer.deploy()
  }

  event.locals.server = ganacheServer

  return await resolve(event)
}
