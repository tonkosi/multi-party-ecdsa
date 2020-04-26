#!/usr/bin/env bash

target=release

if [ "$#" -ne "2" ]; then
  echo "Please, specify number of parties and threshold."
  exit 1
fi

n=$1
t=$2

echo "$n" > params
echo "$t" >> params
echo "{\"parties\":\"$n\", \"threshold\":\"$t\"}" > params.json

echo "Multi-party ECDSA parties: $n, threshold: $t"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~~~      KEY GENERATION PROTOCOL      ~~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ""

rm keys?.store
killall sm_manager gg18_keygen_client gg18_sign_client 2> /dev/null

./target/release/examples/sm_manager &

sleep 2

for i in $(seq 1 $n)
do
  echo "Creating key-gen client #$i out of $n"
  ./target/$target/examples/gg18_keygen_client http://127.0.0.1:8001 keys$i.store &
  sleep 2
done
