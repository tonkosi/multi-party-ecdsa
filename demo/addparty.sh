#!/usr/bin/env bash

target=release

file_as_string=`cat params.json`

n=`echo "$file_as_string" | cut -d "\"" -f 4 `
t=`echo "$file_as_string" | cut -d "\"" -f 8 `

echo "Multi-party ECDSA parties: $n, threshold: $t"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~~~        NEW PARTY PROTOCOL         ~~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ""

killall gg18_keygen_client gg18_sign_client gg18_addparty_client 2> /dev/null

sleep 2

for i in $(seq 1 $((n + 1)))
do
  echo "Creating key-gen client #$i out of $n"
  ./target/$target/examples/gg18_addparty_client http://127.0.0.1:8001 keys$i.store &
  sleep 2
done

echo "$((n + 1))" > params
echo "$t" >> params
echo "{\"parties\":\"$((n + 1))\", \"threshold\":\"$t\"}" > params.json
