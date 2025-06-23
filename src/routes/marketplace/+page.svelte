<script lang="ts">
  import { ethers } from 'ethers'
  import { onMount } from 'svelte'
  import { goto } from '$app/navigation'
  import { wallet, collection } from '$lib/store'
  import { GameFactory } from '$lib/models/game/GameFactory'
  import Marketplace from './components/Marketplace.svelte'

  import type { PageData } from './$types'
  import type { NFT } from '$lib/server/db/types/NFT'

  export let data: PageData

  $: {
    if (data?.nft?.collection) {
      collection.set(data.nft.collection)
    }
  }

  let container: HTMLDivElement

  onMount(async () => {
    if (!window.ethereum?.isMetaMask || !(await $wallet.isConnected())) {
      return goto('/')
    }

    await $wallet.setProvider(new ethers.BrowserProvider(window.ethereum))

    $wallet.createNFTContract(data.nft.address, data.nft.abi)
    $wallet.createMarketplaceContract(data.marketplace.address, data.marketplace.abi)

    wallet.set($wallet)

    GameFactory.container(container)
      .players($collection.filter((nft: NFT) => nft.owner.toLowerCase() === $wallet.account))
      .build()
  })
</script>

<Marketplace />
<div id="canvas" bind:this={container} />

<style lang="scss">
  #canvas {
    width: 100vw;
    height: 100vh;
    background: url('/images/background.png') no-repeat center center fixed;
    background-size: cover;
    -o-background-size: cover;
    -moz-background-size: cover;
    -webkit-background-size: cover;
  }
</style>
