import type { GanacheServer } from '$lib/GanacheServer'

declare global {
  interface Window {
    ethereum: MetaMaskInpageProvider
  }
  namespace App {
    interface Locals {
      server: GanacheServer
    }
    // interface Error {}
    // interface PageData {}
    // interface Platform {}
  }
}

export {}
