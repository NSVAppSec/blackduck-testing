<script lang="ts">
  import BuyView from './BuyView.svelte'
  import InfoView from './InfoView.svelte'
  import SellView from './SellView.svelte'
  import { view, selected } from '$lib/store'
  import { View } from '$lib/types/View'
  import { AttributeType } from '$lib/types/Metadata'

  const findTraitValue = (trait: AttributeType) =>
    $selected?.metadata.attributes?.find((a) => a.trait_type === trait)?.value

  $: health = findTraitValue(AttributeType.HEALTH)
  $: attack = findTraitValue(AttributeType.ATTACK)
  $: defense = findTraitValue(AttributeType.DEFENSE)
</script>

<div class="nft-detail-view__container">
  <div class="navigation__container">
    <button
      on:click={() => {
        selected.set(null)
        view.set(View.INFO)
      }}>&lt; Marketplace</button>
  </div>
  <div class="main__container">
    <div class="nft__container">
      <img src={`/images/nfts/${$selected?.metadata.trace}/idle.gif`} alt="NFT Animation" />
      <div class="stats">
        <div class="stat__item">
          <img src="/images/heart.png" alt="Health" /><span>{health}</span>
        </div>
        <div class="stat__item">
          <img src="/images/sword32.png" alt="Attack" /><span>{attack}</span>
        </div>
        <div class="stat__item">
          <img src="/images/shield32.png" alt="Defense" /><span>{defense}</span>
        </div>
      </div>
    </div>
    {#if $view === View.INFO}
      <InfoView />
    {:else if $view === View.BUY}
      <BuyView />
    {:else if $view === View.SELL}
      <SellView />
    {/if}
  </div>
</div>

<style lang="scss">
  .nft-detail-view__container {
    height: 100%;
    .navigation__container {
      button {
        all: unset;
        margin-top: 20px;
        cursor: pointer;
        font-size: 1.8rem;
      }
    }
    .main__container {
      display: grid;
      grid-template-columns: 400px auto;
      .nft__container {
        position: relative;
        img {
          width: 400px;
        }
        .stats {
          width: 100%;
          bottom: 5px;
          position: absolute;
          display: flex;
          padding: 0 60px;
          justify-content: space-between;
          .stat__item {
            display: grid;
            grid-template-columns: 35px auto;
            align-items: center;
            img {
              width: 24px;
            }
            span {
              font-size: 1.4rem;
            }
          }
        }
      }
    }
  }
</style>
