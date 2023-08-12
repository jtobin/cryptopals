#!/usr/bin/env bash

fil=$1

# use these if one needs to resume a broken loop
lidx=$2  # byte idx to start at
llas=$3  # time the last comparison took
lgot=$4  # MAC we've guessed thus far

if [[ -z "$fil" ]]; then
  echo "no file specified. bailing out.."
  exit 1
fi

if [[ -z "$lidx" ]]; then
  lidx=0
  llas=0.049
  lgot=""
fi

sup=$((39 - $lidx))
sig="$lgot""$(printf '0%.0s' $(seq 0 $sup))"

hos="localhost:3000"
got="$lgot"

attempt() {
  local res=$(curl -o /dev/null --silent -Iw "%{http_code}\n" "$1")
  echo "$res"
}

weld() {
  echo "$hos""/hmac?safe=false&file=""$fil""&signature=""$1"
}

las="$llas"

for j in $(seq $lidx 2 38); do
  etc="${sig:$((j+2))}"

  echo "present MAC guess: $sig"
  echo "working on next byte (hexstring index $j).."

  for b in {0..255}; do
    byt=$(printf "%02x" $b)

    can="$got""$byt""$etc"
    url=$(weld $can)

    org=$(date +%s.%N)
    try=$(attempt $url)
    end=$(date +%s.%N)

    tim=$(echo "$end - $org" | bc -l)
    dif=$(echo "$tim - $las" | bc -l)

    if (($try == 500)); then
      lon=$(echo "$dif > 0.05" | bc -l)
      if (( $lon == 1 )); then
        got="$got""$byt"
        sig="$got""$etc"
        las=$tim
        echo "found byte $byt"
        break
      elif (($b == 255)); then
        echo "couldn't find byte value. bailing out.."
        echo "got: $got"
        echo "tim: $tim"
        exit 1
      fi
    elif (($try == 200)); then
      echo "succeeded"
      echo "file: $fil"
      echo "hmac: $sig"
      exit 0
    else
      echo "something really weird happened.."
    fi
  done
done

