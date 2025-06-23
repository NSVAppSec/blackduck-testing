import fs from 'fs'
import path from 'path'
import { Contract, JsonRpcSigner, ethers } from 'ethers'
import type { Sources } from '$lib/types/Source'

const CONTRACTS_PATH: string = './src/lib/contracts'

export class SmartContract {
  private _name: string
  private _content: string
  private _abi: string
  private _bytecode: string
  private _contract: Contract
  private _dependencies: SmartContract[]

  constructor(name: string, dependencies: SmartContract[] = []) {
    this._name = name
    this._dependencies = dependencies
    this._content = fs.readFileSync(path.join(CONTRACTS_PATH, this.fullname), {
      encoding: 'utf8',
      flag: 'r'
    })
  }

  get abi(): string {
    return this._abi
  }

  get address(): string {
    return this._contract.target as string
  }

  get contract(): Contract {
    return this._contract
  }

  get fullname(): string {
    return `${this._name}.sol`
  }

  set dependencies(dependencies: SmartContract | SmartContract[]) {
    this._dependencies = Array.isArray(dependencies) ? dependencies : [dependencies]
  }

  get dependencies(): SmartContract[] {
    return this._dependencies
  }

  get sources(): Sources {
    return this._dependencies.reduce(
      (sources, dependency: SmartContract) => {
        sources[dependency.fullname] = { content: dependency._content }
        return sources
      },
      { [this.fullname]: { content: this._content } }
    )
  }

  async deploy(compiledOutput: any, signer: JsonRpcSigner): Promise<void> {
    const deployContract = async (dep: SmartContract, parameters: any[] = []) => {
      dep._abi = compiledOutput.contracts[dep.fullname][dep._name].abi
      dep._bytecode = compiledOutput.contracts[dep.fullname][dep._name].evm.bytecode.object

      const factory = new ethers.ContractFactory(dep._abi, dep._bytecode, signer)
      const contract = await factory.deploy(...parameters)

      dep._contract = new ethers.Contract(contract.target as string, dep._abi, signer)
    }

    for (const dep of this._dependencies) {
      await deployContract(dep)
    }

    await deployContract(this, [signer.address, ...this._dependencies.map((d) => d.address)])
  }
}
