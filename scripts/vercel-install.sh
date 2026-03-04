#!/bin/bash
# Install script for Vercel
# This configures git to use the GITHUB_PAT environment variable for authentication
# before attempting to npm install private dependencies.

if [ -n "$GITHUB_PAT" ]; then
  echo "Configuring git for private GitHub repositories..."
  # Clean potential old configs
  git config --global --unset-all url."https://${GITHUB_PAT}@github.com/".insteadOf || true
  
  # Set new configs using x-oauth-basic prefix for PAT
  git config --global url."https://x-oauth-basic:${GITHUB_PAT}@github.com/".insteadOf "ssh://git@github.com/"
  git config --global url."https://x-oauth-basic:${GITHUB_PAT}@github.com/".insteadOf "git@github.com:"
  git config --global url."https://x-oauth-basic:${GITHUB_PAT}@github.com/".insteadOf "https://github.com/"
else
  echo "Warning: GITHUB_PAT environment variable is not set."
fi

echo "Running npm install..."
npm install
