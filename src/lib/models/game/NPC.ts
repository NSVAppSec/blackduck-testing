import Konva from 'konva'
import { Animation } from '$lib/types/Animation'

const WIDTH: number = 250
const HEIGHT: number = 250
const VELOCITY: number = 2

const GENERATION_RADIUS: number = 250
const CHECKPOINT_RADIUS: number = 200
const CHECKPOINT_NUMBER: number = 8

const ANIMATIONS = {
  [Animation.IDLE]: { frames: 18 },
  [Animation.BLINKING]: { frames: 18 },
  [Animation.KICKING]: { frames: 12 },
  [Animation.WALKING]: { frames: 24 },
  [Animation.SLASHING]: { frames: 12 }
}

interface Point {
  x: number
  y: number
}

export class NPC {
  stage: Konva.Stage
  sprite: Konva.Sprite

  points: Point[] = []
  isMoving: boolean
  destination: Point

  constructor(trace: string, stage: Konva.Stage) {
    this.stage = stage

    const imageObj = new Image()
    const startAt: Point = this.createPotentialPoint()

    this.sprite = new Konva.Sprite({
      x: startAt.x - WIDTH / 2 + 20, // padding to match the foot position
      y: startAt.y - HEIGHT + 30, // padding to match the foot position
      width: WIDTH,
      height: HEIGHT,
      image: imageObj,
      animation: Animation.IDLE,
      animations: this.createAnimationFrames(),
      frameRate: 13,
      frameIndex: 0
    })

    imageObj.onload = () => {
      stage.getLayers()[0].add(this.sprite)
      this.sprite.start()
      this.startRoute()
    }

    imageObj.src = `/images/nfts/${trace}/spritesheet.png`

    this.generateRoute(CHECKPOINT_NUMBER)
  }

  private createAnimationFrames(): Record<string, number[]> {
    return Object.entries(ANIMATIONS).reduce((animations, [key, { frames }], index) => {
      animations[key] = Array.from({ length: frames }, (_, i) => [
        WIDTH * i,
        HEIGHT * index,
        WIDTH,
        HEIGHT
      ]).flat()
      return animations
    }, {} as Record<string, number[]>)
  }

  private getFootPosition() {
    return {
      x: this.sprite.position().x + WIDTH / 2 + 20,
      y: this.sprite.position().y + HEIGHT - 30
    }
  }

  private setFootPosition(x: number, y: number) {
    this.sprite.x(this.sprite.position().x + x).y(this.sprite.position().y + y)
  }

  private setAnimation(animation: Animation, scaleX = 1) {
    this.sprite
      .scaleX(scaleX)
      .offsetX(scaleX === -1 ? WIDTH : 0)
      .animation(animation)
      .start()
  }

  private calculateDistance(a: Point, b: Point) {
    const dx = a.x - b.x
    const dy = a.y - b.y
    return Math.sqrt(dx * dx + dy * dy)
  }

  // x: adds 150px padding to the left and right
  // y: adds 45% padding to the top and 150px to the bottom
  private createPotentialPoint(): Point {
    return {
      x: 150 + Math.random() * (this.stage.width() - 300),
      y: this.stage.height() * 0.45 + Math.random() * (this.stage.height() * 0.55 - 150)
    }
  }

  private generateRoute(checkpoints: number): void {
    while (this.points.length < checkpoints) {
      const potentialPoint: Point = this.createPotentialPoint()
      if (this.calculateDistance(potentialPoint, this.getFootPosition()) > GENERATION_RADIUS) {
        this.points.push(potentialPoint)
      }
    }
  }

  private findNextCheckpoint(): Point {
    while (true) {
      const potentialDest = this.points[Math.floor(Math.random() * this.points.length)]
      if (this.calculateDistance(potentialDest, this.getFootPosition()) > CHECKPOINT_RADIUS) {
        return potentialDest
      }
    }
  }

  private moveTowardsDestination(): Promise<void> {
    return new Promise((resolve) => {
      const currentPosition = this.getFootPosition()

      const dx = this.destination.x - currentPosition.x
      const dy = this.destination.y - currentPosition.y
      const angle = Math.atan2(dy, dx)

      this.setFootPosition(Math.cos(angle) * VELOCITY, Math.sin(angle) * VELOCITY)
      this.setAnimation(Animation.WALKING, dx < 0 ? -1 : 1)

      // walking speed is 1/40 of a second
      setTimeout(() => resolve(), 1000 / 40)
    })
  }

  private hasReachedDestination(): boolean {
    return this.calculateDistance(this.getFootPosition(), this.destination) < 2
  }

  private async startRoute(): Promise<void> {
    this.isMoving = true
    this.destination = this.findNextCheckpoint()
    while (this.isMoving) {
      await this.moveTowardsDestination()

      if (this.hasReachedDestination()) {
        this.setAnimation(Animation.IDLE, this.sprite.scaleX())

        // waits between 10 and 45 secons to start walking again
        const delay = Math.floor(Math.random() * (45 - 10 + 1) + 10) * 1000
        await new Promise((resolve) => setTimeout(resolve, delay))

        this.destination = this.findNextCheckpoint()
        this.isMoving = !!this.destination
      }
    }
  }
}
