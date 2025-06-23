<script lang="ts">
  import { View } from '$lib/types/View'
  import { view, wallet, selected } from '$lib/store'
  import ProgressBar from './ProgressBar.svelte'

  let amount = undefined

  let isProgressBar = false

  const createSellOrder = async () => {
    if (amount && $selected) {
      isProgressBar = true
      await $wallet.createSellOrder($selected.id, amount)
    }
  }
</script>

<div class="sell__container">
  {#if isProgressBar}
    <div class="title__container">
      <h2>Please follow MetaMask instructions in order to complete the sale</h2>
    </div>
    <div class="progress-bar__container">
      <ProgressBar />
    </div>
  {:else}
    <div class="title__container">
      <h2>Are you sure you want to sell this NFT?</h2>
      <p>Please set the selling price:</p>
    </div>
    <div class="form__container">
      <input type="number" id="amount" name="amount" placeholder="10" required bind:value={amount} />
      <label for="amount"><strong>EST</strong></label>
    </div>
    <div class="action__buttons">
      <button class="accept" on:click={createSellOrder} />
      <button class="cancel" on:click={() => view.set(View.INFO)} />
    </div>
  {/if}
</div>

<style lang="scss">
  .sell__container {
    font-size: 1.4rem;
    .title__container {
      h2 {
        margin-top: 0;
        text-align: center;
      }
    }
    .progress-bar__container {
      padding: 0 1rem;
    }
    .form__container {
      strong {
        color: #33281f;
      }
      input {
        all: unset;
        width: 290px;
        padding: 10px;
        border: 2px solid #33281f;
        border-radius: 5px;
        background: none;
      }
      input::-webkit-outer-spin-button,
      input::-webkit-inner-spin-button {
        -webkit-appearance: none;
        margin: 0;
      }
    }
    .action__buttons {
      display: flex;
      margin-top: 2rem;
      button {
        all: unset;
        width: 190px;
        height: 60px;
        cursor: pointer;
        background-size: contain;
        background-repeat: no-repeat;
        background-color: transparent;
      }
      .accept {
        background-image: url('/assets/buttons/accept-button.png');
        &:hover {
          background-image: url('/assets/buttons/accept-button-pressed.png');
        }
      }
      .cancel {
        background-image: url('/assets/buttons/cancel-button.png');
        &:hover {
          background-image: url('/assets/buttons/cancel-button-pressed.png');
        }
      }
    }
  }
</style>
