var fs = require('fs')
var path = require('path')
const crypto = require('crypto')

const base = {
  Ethereal: { health: 100, attack: 100, defense: 150 },
  Mystic: { health: 150, attack: 150, defense: 200 },
  Arcane: { health: 200, attack: 250, defense: 250 },
  Celestial: { health: 250, attack: 350, defense: 300 }
}

function generateStats(category) {
  return [
    { trait_type: 'category', value: category },
    { trait_type: 'health', value: Math.floor(base[category].health + Math.random() * 50) },
    { trait_type: 'attack', value: Math.floor(base[category].attack + Math.random() * 50) },
    { trait_type: 'defense', value: Math.floor(base[category].defense + Math.random() * 50) }
  ]
}

function slugify(str) {
  str = str.replace(/^\s+|\s+$/g, '') // trim leading/trailing white space
  str = str.toLowerCase() // convert string to lowercase
  str = str
    .replace(/[^a-z0-9 -]/g, '') // remove any non-alphanumeric characters
    .replace(/\s+/g, '-') // replace spaces with hyphens
    .replace(/-+/g, '-') // remove consecutive hyphens
  return str
}

function walk(dir) {
  let results = []
  const list = fs.readdirSync(dir)
  list.forEach(function (file) {
    file = path.join(dir, file)
    const stat = fs.statSync(file)
    if (stat && stat.isDirectory()) {
      results.push(file)
      results = results.concat(walk(file))
    }
  })
  return results
}

const outputDir = './output'

const folders = walk(outputDir)

folders.forEach((folder) => {
  if ((folder.match(/\//g) || []).length < 2) {
    return
  }

  var nftInfo = folder.match(/([^\/]*)\/*$/)[1]

  var [name, category] = nftInfo.split('-')

  let nft = {
    name: name.trim(),
    description: '',
    image: '',
    trace: crypto.createHash('md5').update(name.trim()).digest('hex'),
    attributes: generateStats(category.trim())
  }

  fs.writeFileSync(`./${folder}/${slugify(name.trim())}-nft.json`, JSON.stringify(nft), 'utf8')
})

// let stats = generateStats('Celestial');
// console.log(stats);
