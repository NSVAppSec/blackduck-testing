<script lang="ts">
  import { progressBar } from "$lib/store"
</script>

<div class="progress-bar__container">
  <div class="info__container">
    <span>{$progressBar?.message}</span>
  </div>
  <div class="meter">
    <span style="width: {$progressBar?.percentage}%"></span>
  </div>
</div>

<style lang="scss">

  .progress-bar__container {

    .info__container {
      text-align: center;
      margin-bottom: 1rem;
    }

    .meter {
      box-sizing: content-box;
      height: 22px;
      position: relative;
      background: #352a25;
      border-radius: 25px;
      padding: 6px;
      box-shadow: inset 0 -1px 1px rgba(255, 255, 255, 0.3);
    }

    .meter > span {
      display: block;
      height: 100%;
      border-top-right-radius: 8px;
      border-bottom-right-radius: 8px;
      border-top-left-radius: 20px;
      border-bottom-left-radius: 20px;
      background-color: #a2724a;
      background-image: linear-gradient(center bottom, #a2724a 37%, #a2724a 69%);
      box-shadow: inset 0 2px 9px rgba(255, 255, 255, 0.3),
        inset 0 -2px 6px rgba(0, 0, 0, 0.4);
      position: relative;
      overflow: hidden;
    }

    .meter > span:after {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      bottom: 0;
      right: 0;
      background-image: linear-gradient(
        -45deg,
        rgba(255, 255, 255, 0.2) 25%,
        transparent 25%,
        transparent 50%,
        rgba(255, 255, 255, 0.2) 50%,
        rgba(255, 255, 255, 0.2) 75%,
        transparent 75%,
        transparent
      );
      z-index: 1;
      background-size: 50px 50px;
      animation: move 2s linear infinite;
      border-top-right-radius: 8px;
      border-bottom-right-radius: 8px;
      border-top-left-radius: 20px;
      border-bottom-left-radius: 20px;
      overflow: hidden;
    }

    @keyframes move {
      0% {
        background-position: 0 0;
      }
      100% {
        background-position: 50px 50px;
      }
    }

  }

</style>
