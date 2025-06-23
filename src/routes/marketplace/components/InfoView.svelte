<script lang="ts">
  import { View } from '$lib/types/View'
  import { view, wallet, selected } from '$lib/store'

  const onBuy = () => view.set(View.BUY)
  const onSell = () => view.set(View.SELL)

  const onCancelSale = async () => {
    if ($selected) {
      await $wallet.cancelSellOrder($selected.id)
    }
  }

  let buttons: any = []

  $: {
    const isOnSale = Boolean($selected?.amount)
    const isOwnedByUser = $selected?.owner?.toLowerCase() === $wallet?.account

    if (isOnSale && !isOwnedByUser) {
      buttons.push({ class: 'buy-nft', click: onBuy })
    }

    if (!isOnSale && isOwnedByUser) {
      buttons.push({ class: 'sell-nft', click: onSell })
    }

    if (isOnSale && isOwnedByUser) {
      buttons.push({ class: 'cancel-sale-nft', click: onCancelSale })
    }
  }
</script>

<div class="info__container">
  <div class="info__item rm-mg-top"><p><strong>Name:</strong> {$selected?.metadata.name}</p></div>
  <div class="info__item">
    <p><strong>Description:</strong> {$selected?.metadata.description}</p>
  </div>
  <div class="info__item actions">
    {#each buttons as button}
      <button class={button.class} on:click={button.click} />
    {/each}
  </div>
</div>

<style lang="scss">
  .info__container {
    .info__item {
      font-size: 1.4rem;
      strong {
        color: #33281f;
      }
      &.rm-mg-top {
        p {
          margin-top: 0;
        }
      }
      &.actions {
        button {
          all: unset;
          width: 190px;
          height: 60px;
          cursor: pointer;
          background-size: contain;
          background-repeat: no-repeat;
          background-color: transparent;
        }
        .buy-nft {
          background-image: url('/assets/buttons/buy-button.png');
          &:hover {
            background-image: url('/assets/buttons/buy-button-pressed.png');
          }
        }
        .sell-nft {
          background-image: url('/assets/buttons/sell-button.png');
          &:hover {
            background-image: url('/assets/buttons/sell-button-pressed.png');
          }
        }
        .cancel-sale-nft {
          background-image: url('/assets/buttons/cancel-sale-button.png');
          &:hover {
            background-image: url('/assets/buttons/cancel-sale-button-pressed.png');
          }
        }
      }
    }
  }
</style>
