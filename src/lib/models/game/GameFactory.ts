import { Game } from './Game'
import type { NFT } from '$lib/server/db/types/NFT'

export class GameFactory {
  private static _players: NFT[]
  private static _container: HTMLDivElement

  static container(container: HTMLDivElement): typeof GameFactory {
    this._container = container
    return this
  }

  static players(players: NFT | NFT[]): typeof GameFactory {
    this._players = Array.isArray(players) ? players : [players]
    return this
  }

  static build(): Game {
    return new Game(this._container, this._players)
  }
}
