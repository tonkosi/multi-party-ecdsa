#!/usr/bin/env bash

target=release

file_as_string=`cat params.json`

n=`echo "$file_as_string" | cut -d "\"" -f 4 `
t=`echo "$file_as_string" | cut -d "\"" -f 8 `

expected_parties=$((t + 1))
if [ "$#" -ne "$expected_parties" ]; then
  echo "Exactly $expected_parties parties are expected!"
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

echo "Multi-party ECDSA parties: $n, threshold: $t"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~~~     ECDSA SIGNATURE PROTOCOL      ~~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ""

killall gg18_keygen_client gg18_sign_client 2> /dev/null

sleep 2

for party in "$@"; do
  echo "Signing for client #$party..."
  ./target/$target/examples/gg18_sign_client http://127.0.0.1:8001 keys$party.store "PORUKA" &
  sleep 2
done
