#!/bin/bash

normalize_name() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | tr '[:space:]_' '-' | sed 's/-*$//'
}

# nfts folder path
nfts_dir="./nfts"

# output folder path
output_dir="$nfts_dir-out"

# backgrounds folder path
backgrounds_dir="./backgrounds"

# wanted animation list
animations=("Idle" "Idle Blinking" "Kicking" "Walking" "Slashing")

# loop over all nft types
for nft_type in "$nfts_dir"/*; do
  nft_type_name=$(basename "$nft_type")
  normalized_nft_type_name=$(normalize_name "$nft_type_name")

  # loop over each nft
  for nft in "$nft_type"/*; do
    nft_name=$(basename "$nft")
    normalized_nft_name=$(normalize_name "$nft_name")

    output_animation_dir="$output_dir/$normalized_nft_type_name/$normalized_nft_name/avatar"
    mkdir -p "$output_animation_dir/tmp"
    mkdir -p "$output_dir/$normalized_nft_type_name/$normalized_nft_name/spritesheet"

    i=0
    for animation_name in "${animations[@]}"; do
      normalized_animation_name=$(normalize_name "$animation_name")

      # define the animation path
      animation="$nft/PNG/PNG Sequences/$animation_name"

      # check if animation folder exists
      if [[ -d "$animation" ]]; then

        mkdir -p "$output_dir/$normalized_nft_type_name/$normalized_nft_name/$normalized_animation_name/resized"
        mkdir -p "$output_dir/$normalized_nft_type_name/$normalized_nft_name/$normalized_animation_name/animation"
        mkdir -p "$output_dir/$normalized_nft_type_name/$normalized_nft_name/$normalized_animation_name/spritesheet"

        # create nft avatar
        if [ -d "$backgrounds_dir" ] && [ "$animation_name" == "Idle" ]; then

          # picks random background for the avatar
          background=$(ls "$backgrounds_dir"/*.png | shuf -n 1)

          # loop over each animation frame
          for image in "$animation"/*.png; do

            image_name=$(basename "$image")
            
            # create temporal copy of the frame
            temp_image="$output_animation_dir/tmp/$image_name"
            cp "$image" "$temp_image"
            
            # add background to each animation frame
            convert "$background" "$temp_image" -gravity center -composite "$temp_image"

          done

          # create avatar gif with background images
          convert -dispose Background -loop 0 "$output_animation_dir"/tmp/*.png "$output_animation_dir/${normalized_nft_name}_${normalized_animation_name}.gif"
          
          # delete temporal files
          rm -rf "$output_animation_dir"/tmp

        fi

        # create animation gif
        convert -dispose Background -loop 0 "$animation"/*.png "$output_dir/$normalized_nft_type_name/$normalized_nft_name/$normalized_animation_name/animation/${normalized_nft_name}_${normalized_animation_name}.gif"
        
        # resize and crop the sprite
        for file in "$animation"/*.png; do
          basename=$(basename "$file")
          convert "$file" -resize 300x300 -crop 250x250+50+20 +repage "$output_dir/$normalized_nft_type_name/$normalized_nft_name/$normalized_animation_name/resized/$basename"
        done

        # create the spritesheet
        convert $output_dir/$normalized_nft_type_name/$normalized_nft_name/$normalized_animation_name/resized/*.png +append "$output_dir/$normalized_nft_type_name/$normalized_nft_name/$normalized_animation_name/spritesheet/spritesheet.png"
        cp "$output_dir/$normalized_nft_type_name/$normalized_nft_name/$normalized_animation_name/spritesheet/spritesheet.png" "$output_dir/$normalized_nft_type_name/$normalized_nft_name/spritesheet/$i.png"
        rm -rf "$output_dir/$normalized_nft_type_name/$normalized_nft_name/$normalized_animation_name/resized"

        ((++i))
      fi
    done

    # convert each animation spritesheet into a big spritesheet
    convert $output_dir/$normalized_nft_type_name/$normalized_nft_name/spritesheet/*.png -append -transparent white "$output_dir/$normalized_nft_type_name/$normalized_nft_name/spritesheet/spritesheet.png"

  done
done