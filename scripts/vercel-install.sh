#!/bin/bash
# Install script for Vercel
# This configures git to use HTTPS for GitHub dependency resolution.

if [ -n "$GITHUB_PAT" ]; then
  echo "Injecting GITHUB_PAT into package.json and package-lock.json for Vercel deployment..."
  GIT_BASE_URL="https://x-oauth-basic:${GITHUB_PAT}@github.com/"

  # Replace in package.json
  sed -i "s|github:einmalmaik/singra-premium|git+https://x-oauth-basic:${GITHUB_PAT}@github.com/einmalmaik/singra-premium.git|g" package.json
  sed -i "s|git+https://github.com/einmalmaik/singra-premium.git|git+https://x-oauth-basic:${GITHUB_PAT}@github.com/einmalmaik/singra-premium.git|g" package.json
  sed -i "s|https://github.com/einmalmaik/singra-premium.git|git+https://x-oauth-basic:${GITHUB_PAT}@github.com/einmalmaik/singra-premium.git|g" package.json

  # Replace in package-lock.json if it exists
  if [ -f package-lock.json ]; then
    sed -i "s|git+ssh://git@github.com/einmalmaik/singra-premium.git|git+https://x-oauth-basic:${GITHUB_PAT}@github.com/einmalmaik/singra-premium.git|g" package-lock.json
    sed -i "s|ssh://git@github.com/einmalmaik/singra-premium.git|git+https://x-oauth-basic:${GITHUB_PAT}@github.com/einmalmaik/singra-premium.git|g" package-lock.json
    sed -i "s|git+https://github.com/einmalmaik/singra-premium.git|git+https://x-oauth-basic:${GITHUB_PAT}@github.com/einmalmaik/singra-premium.git|g" package-lock.json
  fi
else
  echo "Warning: GITHUB_PAT environment variable is not set."
  GIT_BASE_URL="https://github.com/"
fi

# Always rewrite SSH style URLs to HTTPS in this build environment.
git config --global url."${GIT_BASE_URL}".insteadOf ssh://git@github.com/
git config --global url."${GIT_BASE_URL}".insteadOf git@github.com:
git config --global url."${GIT_BASE_URL}".insteadOf https://github.com/

echo "Running npm install..."
npm install