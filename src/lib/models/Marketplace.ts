import Database from '$lib/server/db'
import { SmartContract } from './ SmartContract'
import { MarketplaceEvent } from '$lib/types/MarketplaceEvents'

import type { NFT } from '$lib/server/db/types/NFT'
import type { Metadata } from '$lib/types/Metadata'
import type { ContractTransactionReceipt, JsonRpcSigner, LogDescription } from 'ethers'

export class Marketplace extends SmartContract {
  signer: JsonRpcSigner
  nft: SmartContract
  currency: SmartContract

  constructor(signer: JsonRpcSigner) {
    super('NFTMarketplace')

    this.signer = signer
    this.nft = new SmartContract('CryptorianRelics')
    this.currency = new SmartContract('EtherStone')
    this.dependencies = [this.currency, this.nft]
  }

  async deploy(compileOutput: any): Promise<void> {
    await super.deploy(compileOutput, this.signer)
    await (await this.nft.contract.setApprovalForAll(this.address, true)).wait()
    this.startEventListener()
  }

  async mintNFTs(nfts: string[], address: string = this.signer.address): Promise<void> {
    for (const nft of nfts) {
      const receipt: ContractTransactionReceipt = await (
        await this.nft.contract.safeMint(address, nft)
      ).wait()

      const log: LogDescription = receipt.logs
        .map((log) => ({ topics: [...log.topics], data: log.data }))
        .map((log) => this.nft.contract.interface.parseLog(log))
        .find((event) => event && event.name === 'Transfer')!

      const owner: string = log?.args[1]
      const nftID: number = log?.args[2].toString() as number

      Database.createNFT(owner, nftID, nft)

      if (address == this.signer.address) {
        await (await this.contract.postSellOrder(nftID, Math.floor(Math.random() * 15) + 1)).wait()
      }
    }
  }

  async fetchNFTMetadata(nfts: NFT[]): Promise<NFT[]> {
    return Promise.all(
      nfts.map(async (nft) => {
        const response = await fetch(`https://ipfs.io/ipfs/${nft.ipfs}`)
        const metadata: Metadata = await response.json()
        return { ...nft, metadata }
      })
    )
  }

  async mintEtherStones(amount: number, accounts: string[]): Promise<void> {
    for (const account of accounts) {
      await (await this.currency.contract.mint(account, BigInt(amount) * BigInt(10 ** 18))).wait()
    }
  }

  private startEventListener(): void {
    this.contract.on(MarketplaceEvent.SELL_ORDER_LISTED, (owner, id, amount) => {
      Database.createSellOrder({ owner, nftID: id, amount })
    })
    this.contract.on(MarketplaceEvent.SELL_ORDER_CANCELLED, (id) => {
      Database.cancelSellOrder(id)
    })
  }
}
