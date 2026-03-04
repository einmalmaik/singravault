#!/bin/bash
# Install script for Vercel
# This configures git to use the GITHUB_PAT environment variable for authentication
# before attempting to npm install private dependencies.

if [ -n "$GITHUB_PAT" ]; then
  echo "Injecting GITHUB_PAT into package.json and package-lock.json for Vercel deployment..."
  
  # Replace in package.json
  sed -i "s|github:einmalmaik/singra-premium|git+https://x-oauth-basic:${GITHUB_PAT}@github.com/einmalmaik/singra-premium.git|g" package.json
  
  # Replace in package-lock.json if it exists
  if [ -f package-lock.json ]; then
    sed -i "s|git+ssh://git@github.com/einmalmaik/singra-premium.git|git+https://x-oauth-basic:${GITHUB_PAT}@github.com/einmalmaik/singra-premium.git|g" package-lock.json
    sed -i "s|ssh://git@github.com/einmalmaik/singra-premium.git|git+https://x-oauth-basic:${GITHUB_PAT}@github.com/einmalmaik/singra-premium.git|g" package-lock.json
  fi
else
  echo "Warning: GITHUB_PAT environment variable is not set."
fi

echo "Running npm install..."
npm install
