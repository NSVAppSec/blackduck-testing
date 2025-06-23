import type { Marketplace } from './Marketplace'
import type { Metadata } from '$lib/types/Metadata'

import { ethers, type BrowserProvider, Contract, JsonRpcSigner } from 'ethers'
import { MetaMask } from '$lib/types/MetaMask'
import { invalidateAll } from '$app/navigation'
import { progressBar } from '$lib/store'

let chainOptions = {
  chainId: '0x15B3',
  chainName: 'Kingdom Of Cryptoria',
  rpcUrls: ['http://127.0.0.1:8545'],
  iconUrls: [],
  nativeCurrency: {
    name: 'ETH',
    symbol: 'ETH',
    decimals: 18
  },
  blockExplorerUrls: ['https://etherscan.io']
}

let tokenOptions = {
  type: 'ERC20',
  options: {
    address: '',
    symbol: 'EST',
    decimals: 18,
    image: 'https://foo.io/token-image.svg'
  }
}

export class Wallet {
  nfts: Metadata[]
  accounts: string[] = []
  marketplace: Marketplace

  private _signer: JsonRpcSigner
  private _provider: BrowserProvider
  private _nftContract: Contract
  private _marketplaceContract: Contract

  get account(): string {
    return this.accounts[0]?.toLowerCase()
  }

  async isConnected() {
    this.accounts = await window.ethereum.request({ method: MetaMask.ACCOUNTS })
    return this.accounts.length > 0
  }

  async setProvider(provider: BrowserProvider): Promise<void> {
    this._provider = provider
    this._signer = await provider.getSigner()
    this.startEventListeners()
  }

  createNFTContract(address: string, abi: string): void {
    this._nftContract = new ethers.Contract(address, abi, this._signer)
  }

  createMarketplaceContract(address: string, abi: string): void {
    this._marketplaceContract = new ethers.Contract(address, abi, this._signer)
  }

  private startEventListeners(): void {
    window.ethereum.on(MetaMask.ON_ACCOUNT_CHANGE, () => window.location.reload())
  }

  async promptChainCreation() {
    await window.ethereum
      .request({ method: MetaMask.ADD_CHAIN, params: [chainOptions] })
      .catch((error: MetaMaskError) => console.log(error))
  }

  async promptTokenCreation(token: string) {
    tokenOptions.options.address = token
    await window.ethereum
      .request({ method: MetaMask.ADD_TOKEN, params: tokenOptions })
      .catch((error: MetaMaskError) => console.log(error))
  }

  // refactor and do error handling
  async createSellOrder(nftID: number, amount: number): Promise<void> {
    try {

      progressBar.set({percentage: 30, message: 'Pending transaction approval (1/3) ...'})

      const addr: string = await this._marketplaceContract.getAddress()
      await (await this._nftContract.approve(addr, nftID)).wait()

      progressBar.set({percentage: 60, message: 'Pending sale approval (2/3) ...'})

      await (await this._marketplaceContract.postSellOrder(nftID, amount)).wait()

      progressBar.set({percentage: 90, message: 'Awaiting confirmation (3/3) ...'})

      setTimeout(async () => await invalidateAll(), 5000)

    } catch (error) {
      console.log('unable to create sell order', error)
    }
  }

  // refactor and do error handling
  async cancelSellOrder(nftID: number): Promise<void> {
    try {
      await (await this._marketplaceContract.cancelSellOrder(nftID)).wait()
      setTimeout(async () => await invalidateAll(), 5000)
    } catch (error) {
      console.log('unable to cancel sell order', error)
    }
  }
}
