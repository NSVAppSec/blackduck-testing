<script lang="ts">
  import { Direction } from '$lib/types/Direction'
  import { Navigation } from '$lib/types/Navigation'
  import { wallet, currentPage, navigation, collection } from '$lib/store'
  import type { NFT } from '$lib/server/db/types/NFT'

  let pages: number[] = []

  $: {
    let filteredNFTs: NFT[] = []
    switch ($navigation) {
      case Navigation.MY_NFTS:
        filteredNFTs = $collection.filter((nft) => nft.owner.toLowerCase() === $wallet?.account)
        break
      case Navigation.ON_SALE:
        filteredNFTs = $collection.filter((nft) => nft.amount != null)
        break
      default:
        filteredNFTs = $collection
        break
    }
    pages = Array.from({ length: Math.ceil(filteredNFTs.length / 6) }, (_, index) => index + 1)
  }

  const navigate = (direction: Direction) => {
    if (direction === Direction.LEFT && $currentPage > 1) {
      currentPage.update((v) => v - 1)
    } else if (direction === Direction.RIGHT && $currentPage < pages.length) {
      currentPage.update((v) => v + 1)
    }
  }
</script>

<div class="pagination">
  <button class="arrow" on:click={() => navigate(Direction.LEFT)}>&lt;</button>
  <div>
    {#each pages as page}
      <button
        class="page"
        class:active={$currentPage == page}
        on:click={() => currentPage.set(page)}>{page}</button>
    {/each}
  </div>
  <button class="arrow" on:click={() => navigate(Direction.RIGHT)}>&gt;</button>
</div>

<style lang="scss">
  .pagination {
    text-align: center;
    font-size: 1.5rem;
    font-family: 'SangSangRockRegular', sans-serif;
    display: grid;
    justify-content: center;
    grid-template-columns: 15px 80px 15px;

    .page,
    .arrow {
      all: unset;
      cursor: pointer;
    }

    .page {
      color: #6e5a44;

      &:not(:last-child) {
        margin-right: 15px;
      }

      &.active {
        color: #33281f;
      }
    }

    .arrow {
      color: #5d4c3a;
    }
  }
</style>
