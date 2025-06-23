<script lang="ts">
  import { onMount } from 'svelte'
  import { wallet } from '$lib/store'
  import { goto } from '$app/navigation'

  import type { PageData } from './$types'

  export let data: PageData

  let isMetaMask = false
  let isConnected = false

  async function connectMetaMask() {
    const accounts = await window?.ethereum
      ?.request({ method: 'eth_requestAccounts' })
      .catch((err: MetaMaskError) => {
        if (err.code === 4001) {
          console.log('Please connect to MetaMask.')
        } else {
          console.error(err)
        }
      })

    if (!accounts) {
      return
    }

    await $wallet.promptChainCreation()
    await $wallet.promptTokenCreation(data.token)

    return goto('/marketplace')
  }

  onMount(async () => {
    isMetaMask = !!window.ethereum?.isMetaMask

    if (!isMetaMask) {
      return
    }

    if (await $wallet.isConnected()) {
      return goto('/marketplace')
    }
  })
</script>

{#if isMetaMask}
  {#if !isConnected}
    <button on:click={connectMetaMask}>Connect with MetaMask</button>
    <br />
    <br />
    <h2>You can use this accounts to play with</h2>
    <!-- {#each data.accounts as account}
			<span>{account.privKey}</span><br />
		{/each} -->
  {/if}
{:else}
  <p>You need to install metamask in order to play</p>
{/if}
