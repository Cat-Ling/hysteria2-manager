#!/bin/bash

# Configuration
BINARY_NAME="hysteria2-manager"
echo "Building"

rm -f $BINARY_NAME

export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

# 3. Build with Flags
# -trimpath     : Removes file system paths from the binary (improves security/reproducibility).
# -ldflags "-s" : Omit the symbol table.
# -ldflags "-w" : Omit the DWARF symbol table (debug info).
go build -trimpath -ldflags="-s -w" -o $BINARY_NAME main.go

if [ $? -eq 0 ]; then
    echo "Build Successful!"
    echo "Output: ./$BINARY_NAME"
    echo "Size:   $(du -h $BINARY_NAME | cut -f1)"
    
    chmod +x $BINARY_NAME
else
    echo "Build Failed."
    exit 1
fi