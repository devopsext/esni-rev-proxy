#!/bin/sh

function build() {
  local localGoRoot="$1"

  local oldGoRoot=$(go env GOROOT)

  if [[ -z "$localGoRoot" ]]; then
    localGoRoot=".GOROOT"
  fi

  local output="$2"
  if [[ -z "$output" ]]; then
    output="esni-rev-proxy"
  fi

  if [[ ! -d "$localGoRoot" ]]; then
    echo "=> Preparing GO ROOT..."
    ./prepareGoRoot.sh "$localGoRoot"
  else
    echo "=> GO ROOT is already prepared, skipping..."
  fi

  echo "=> Building..."
  export GOROOT=$(pwd)/$localGoRoot
  go build -v -o "$output"

  export GOROOT=${oldGoRoot}

}

build "$@"