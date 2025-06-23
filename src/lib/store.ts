import { View } from './types/View'
import { writable } from 'svelte/store'
import { Wallet } from '$lib/models/Wallet'
import { Navigation } from './types/Navigation'
import type { NFT } from './server/db/types/NFT'
import type { Notification } from './types/Notification'

export const currentPage = writable<number>(1)
export const isMarketOpen = writable<boolean>(false)
export const wallet = writable<Wallet>(new Wallet())
export const selected = writable<NFT | null>(null)
export const navigation = writable<Navigation>(Navigation.MY_NFTS)

export const view = writable<View>(View.INFO)
export const collection = writable<NFT[]>([])

export const progressBar = writable<Notification>({ percentage: 10, message: 'Calculating times ...'})
