export enum AttributeType {
  CATEGORY = 'category',
  HEALTH = 'health',
  ATTACK = 'attack',
  DEFENSE = 'defense'
}

export interface Attribute {
  trait_type: AttributeType
  value: number | string
}

export interface Metadata {
  name: string
  description: string
  image: string
  trace: string
  attributes: Attribute[]
  owner: string
  owned: boolean
}
