#!/bin/bash

set -e

cd "$(dirname "$0")/.."

echo "Running golden vector validation..."
go run ./golden validate

echo "Golden vector validation completed successfully"
