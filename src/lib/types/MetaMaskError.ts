interface MetaMaskError extends Error {
  message: string
  code: number
  data?: unknown
}
