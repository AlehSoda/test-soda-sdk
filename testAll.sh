#!/bin/bash

# Function to print blue text
print_blue() {
    echo -e "\e[94m$1\e[0m"
}

print_blue "Running javascript tests..."
cd js
npx mocha --require esm --grep "^(?!.*should decrypt a message using RSA scheme$)" test.mjs
cd ..

print_blue "Running python tests..."
cd python/soda_python_sdk || exit
python3 -m unittest -v test.py -k "TestMpcHelper"
cd ../..

print_blue "Running golang tests..."
cd golang_cli
go mod download
go test -v -count=1 ./...
cd ..

print_blue "Running javascript decrypt test..."
cd js
npx mocha --require esm --grep "should decrypt a message using RSA scheme" test.mjs
cd ..

print_blue "Running python decrypt test..."
cd python/soda_python_sdk || exit
python3 -m unittest -v test.py -k "TestDecrypt"
cd ../..
