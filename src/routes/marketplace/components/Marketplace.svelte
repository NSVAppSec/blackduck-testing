<script lang="ts">
  import Viewer from './Viewer.svelte'
  import Navigation from './Navigation.svelte'
  import DetailView from './DetailView.svelte'
  import Pagination from './Pagination.svelte'

  import { View } from '$lib/types/View'
  import { view, selected, currentPage, isMarketOpen } from '$lib/store'

  const onClose = () => {
    selected.set(null)
    currentPage.set(1)
    view.set(View.INFO)
    isMarketOpen.set(false)
  }
</script>

<div class="marketplace__container">
  {#if $isMarketOpen}
    <div class="stone-background__container">
      <button class="close-button" on:click={onClose}>
        <img src="/images/close-button.png" alt="Close Button" />
      </button>
      <div class="parchment-background__container">
        {#if $selected}
          <DetailView />
        {:else}
          <Navigation />
          <Viewer />
          <Pagination />
        {/if}
      </div>
    </div>
  {/if}
  <button class="open-marketplace" on:click={() => isMarketOpen.set(true)} />
</div>

<style lang="scss">
  .marketplace__container {
    z-index: 2;
    width: 100%;
    height: 100%;
    position: absolute;
    display: flex;
    align-items: center;
    justify-content: center;

    .open-marketplace {
      padding: 0;
      right: 40px;
      bottom: 40px;
      position: absolute;
      border: none;
      width: 200px;
      height: 70px;
      cursor: pointer;
      background-size: contain;
      background-repeat: no-repeat;
      background-color: transparent;
      background-image: url('/images/open-market.png');
      &:hover {
        background-image: url('/images/open-market-pressed.png');
      }
    }

    .stone-background__container {
      z-index: 3;
      width: 923px;
      height: 619px;
      position: relative;
      display: flex;
      align-items: center;
      justify-content: center;
      background: url('/images/board-stone.png') no-repeat center/contain;
      background-size: contain;
      -o-background-size: contain;
      -moz-background-size: contain;
      -webkit-background-size: contain;

      .close-button {
        all: unset;
        width: 60px;
        height: 60px;
        top: 40px;
        right: -50px;
        position: absolute;
        cursor: pointer;
        img {
          width: 100%;
        }
      }

      .parchment-background__container {
        width: 885px;
        height: 570px;
        padding: 50px;
        font-family: 'SangSangRockRegular', sans-serif;
        background: url('/images/board-parchment.png') no-repeat center/contain;
        background-size: contain;
        -o-background-size: contain;
        -moz-background-size: contain;
        -webkit-background-size: contain;
      }
    }
  }
</style>
