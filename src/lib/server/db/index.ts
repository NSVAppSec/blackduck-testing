import Database from 'better-sqlite3'
import type { NFT } from './types/NFT'

interface SellOrder {
  owner: string
  nftID: number
  amount: number
}

class DatabaseManager {
  static db: Database.Database

  static init() {
    this.db = new Database('./ganache/marketplace.db', { verbose: console.log })

    this.db.exec('DROP TABLE IF EXISTS nfts')
    this.db.exec('DROP TABLE IF EXISTS buy_orders')
    this.db.exec('DROP TABLE IF EXISTS sell_orders')

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS nfts (
        id INTEGER,
        owner TEXT,
        ipfs TEXT
      )
    `)

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS buy_orders (
        id INTEGER,
        owner TEXT,
        nft_id INTEGER,
        amount INTEGER,
        status TEXT
      )
    `)

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sell_orders (
        owner TEXT,
        nft_id INTEGER,
        amount INTEGER
      )
    `)
  }

  static createNFT(owner: string, nftID: number, ipfs: string) {
    this.db.prepare('INSERT INTO nfts VALUES (?, ?, ?)').run(nftID, owner, ipfs)
  }

  static createSellOrder(order: SellOrder) {
    this.db
      .prepare('INSERT INTO sell_orders VALUES (?, ?, ?)')
      .run(order.owner, order.nftID, order.amount)
  }

  static cancelSellOrder(nftID: string) {
    this.db.prepare('DELETE FROM sell_orders WHERE nft_id = ?').run(nftID)
  }

  static getAllNFTs(): NFT[] {
    return this.db
      .prepare(
        `
        SELECT nfts.id, nfts.owner, nfts.ipfs, sell_orders.amount
        FROM nfts LEFT JOIN sell_orders 
        ON nfts.id = sell_orders.nft_id
      `
      )
      .all() as NFT[]
  }

  static getMyNFTs(address: string): NFT[] {
    return this.db.prepare('SELECT * FROM nfts WHERE owner = ?').all(address) as NFT[]
  }
}

DatabaseManager.init()

export default DatabaseManager
