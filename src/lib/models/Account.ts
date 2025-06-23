export class Account {
  pubKey: string
  privKey: string

  constructor(pubKey: string, privKey: string) {
    this.pubKey = pubKey
    this.privKey = privKey
  }
}
