#!/usr/bin/env bash

target=release

file_as_string=`cat params.json`

n=`echo "$file_as_string" | cut -d "\"" -f 4 `
t=`echo "$file_as_string" | cut -d "\"" -f 8 `

expected_parties=$((t + 1))
if [ "$#" -gt "$n" ]; then
  echo "No more than $n can participate in update!"
  echo "Found $#. Abort."
  exit 1
fi

if [ "$#" -le "$t" ]; then
  echo "At least $((t + 1)) parties have to participate in update!"
  echo "Found $#. Abort."
  exit 1
fi

for party in "$@"; do
  if [ "$party" -gt "$n" ]; then
    echo "Invalid party index! Abort."
    exit 1
  fi
  if [ "$party" -lt "1" ]; then
    echo "Invalid party index!. Abort."
    exit 1
  fi
done

echo "Multi-party ECDSA parties: $n, threshold: $t, updating: $#"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~~~        ECDSA SHARES UPDATE        ~~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ""

killall gg18_keygen_client gg18_sign_client gg18_addparty_client gg18_update_client 2> /dev/null

sleep 2

echo "$#" > update_params.json

for party in "$@"; do
  echo "Signing for client #$party..."
  ./target/$target/examples/gg18_update_client http://127.0.0.1:8001 keys$party.store &
  sleep 2
done
