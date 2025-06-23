<script lang="ts">
  import { Navigation } from '$lib/types/Navigation'
  import { AttributeType, type Attribute } from '$lib/types/Metadata'
  import { wallet, currentPage, navigation, selected, collection } from '$lib/store'
  import type { NFT } from '$lib/server/db/types/NFT'

  const rarity = (attributes: Attribute[]) => {
    return attributes.find((a) => a.trait_type === AttributeType.CATEGORY)?.value
  }

  const notFoundMessages: string[] = [
    'Houston, we have a problem. The NFTs have left the building!',
    "We've hit an NFT dry spell here. Time to summon the rain dance!",
    "The NFTs appear to be playing hide and seek, and they're really good at it!",
    "It seems like we've embarked on a ghost hunt. No NFTs detected in this vicinity!",
    "Whoa! It's tumbleweed central here. No NFTs found in this part of the blockchain desert!"
  ]

  let nfts: NFT[] = []

  $: {
    switch ($navigation) {
      case Navigation.MY_NFTS:
        nfts = $collection.filter((nft) => nft.owner.toLowerCase() === $wallet?.account)
        break
      case Navigation.ON_SALE:
        nfts = $collection.filter((nft) => nft.amount != null)
        break
      default:
        nfts = $collection
        break
    }
    nfts = nfts.slice(($currentPage - 1) * 6, $currentPage * 6)
  }
</script>

<div class="nft-viewer__container">
  {#if !nfts?.length}
    <div class="not-found__container">
      <div class="not-found">
        <img src="/images/exclamation-red.png" alt="Not Found" />
        <h2>{notFoundMessages[Math.floor(Math.random() * notFoundMessages.length)]}</h2>
      </div>
    </div>
  {:else}
    {#each nfts as nft}
      <!-- svelte-ignore a11y-click-events-have-key-events -->
      <!-- svelte-ignore a11y-no-static-element-interactions -->
      <div class="nft__container" on:click={() => selected.set(nft)}>
        <span class="rarity {rarity(nft.metadata.attributes)?.toString().toLowerCase()}"
          >{rarity(nft.metadata.attributes)}</span>
        <img src="/images/nfts/{nft.metadata.trace}/idle.gif" alt="NFT Animation" />
        <div class="stats">
          {#each nft.metadata.attributes as attr}
            {#if attr.trait_type === AttributeType.HEALTH}
              <div class="stat__item">
                <img src="/images/heart.png" alt="Health" /><span>{attr.value}</span>
              </div>
            {/if}
            {#if attr.trait_type === AttributeType.ATTACK}
              <div class="stat__item">
                <img src="/images/sword.png" alt="Attack" /><span>{attr.value}</span>
              </div>
            {/if}
            {#if attr.trait_type === AttributeType.DEFENSE}
              <div class="stat__item">
                <img src="/images/shield.png" alt="Defense" /><span>{attr.value}</span>
              </div>
            {/if}
          {/each}
        </div>
      </div>
    {/each}
  {/if}
</div>

<style lang="scss">
  .nft-viewer__container {
    width: 100%;
    height: 370px;
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    align-content: flex-start;

    .not-found__container {
      height: 100%;
      width: 100%;
      display: grid;
      text-align: center;
      align-items: center;
      justify-content: center;

      .not-found {
        width: 500px;
        img {
          width: 60px;
        }
      }
    }

    .nft__container {
      margin: 15px;
      width: 220px;
      height: 150px;
      border: 1px solid#5e4d3a;
      border-radius: 3px;
      position: relative;
      display: grid;
      grid-template-columns: auto auto;
      cursor: pointer;

      .rarity {
        top: -5px;
        left: -10px;
        padding: 2px 8px;
        color: #fff;
        border-radius: 5px;
        position: absolute;

        &.mystic {
          background-color: #8a0bd2;
        }

        &.celestial {
          background-color: #ffd100;
        }

        &.arcane {
          background-color: #08a045;
        }

        &.ethereal {
          background-color: #00b4d8;
        }
      }

      img {
        width: 150px;
      }

      .stats {
        padding: 20px 10px 20px 0;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        .stat__item {
          display: grid;
          grid-template-columns: 25px auto;
          align-items: center;
          img {
            width: 18px;
          }
        }
      }
    }
  }
</style>
