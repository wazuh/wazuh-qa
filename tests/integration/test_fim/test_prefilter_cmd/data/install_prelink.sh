#!/bin/bash

# Check if prelink is installed and if not, install it
$1 | grep -E "prelink.*" || $2 prelink
