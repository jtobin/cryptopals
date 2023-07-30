#!/usr/bin/env bash
declare -i i
i=1690702400
while (($i < 1690708000)); do
  val=$(mt19937 $i 1)
  echo "seed: $i, val: $val"
  if (($val == 1133750118)); then
    echo "seed is $i"
    exit
  else
    i+=1
  fi
done

