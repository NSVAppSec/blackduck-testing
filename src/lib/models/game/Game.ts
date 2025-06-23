import Konva from 'konva'
import { NPC } from './NPC'
import type { NFT } from '$lib/server/db/types/NFT'

export class Game extends Konva.Stage {
  private npcs: NPC[]

  constructor(container: HTMLDivElement, players: NFT[] = []) {
    super({
      container,
      width: container.clientWidth,
      height: container.clientHeight
    })
    this.add(new Konva.Layer())
    this.npcs = players.map((player: NFT) => new NPC(player.metadata?.trace!, this))
  }
}
