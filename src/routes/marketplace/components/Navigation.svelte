<script lang="ts">
  import { Navigation } from '$lib/types/Navigation'
  import { navigation, currentPage } from '$lib/store'

  const onChange = (nav: Navigation) => {
    navigation.set(nav)
    currentPage.set(1)
  }

  const labels = {
    [Navigation.ON_SALE]: 'ON SALE',
    [Navigation.MY_NFTS]: "MY NFT's",
    [Navigation.COLLECTION]: 'COLLECTION'
  }
</script>

<ul>
  {#each Object.values(Navigation) as nav}
    <!-- svelte-ignore a11y-invalid-attribute -->
    <li class:active={$navigation === nav}>
      <a href="#" on:click={() => onChange(nav)}>{labels[nav]}</a>
    </li>
  {/each}
</ul>

<style lang="scss">
  ul {
    list-style-type: none;
    padding-left: 0;
    margin: 10px auto;
    margin-bottom: 30px;
    width: fit-content;

    li {
      display: inline;
      position: relative;

      &:not(:last-child) {
        margin-right: 90px;
      }

      &::after {
        content: '';
        position: absolute;
        left: 0;
        bottom: -5px;
        width: 100%;
        height: 3px;
        background-color: #000;
        visibility: hidden;
      }

      &.active::after {
        visibility: visible;
      }

      a {
        color: #000;
        font-size: 1.7rem;
        text-decoration: none;
      }
    }
  }
</style>
