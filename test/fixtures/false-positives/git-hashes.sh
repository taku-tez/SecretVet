#!/bin/bash
# This file contains git commit hashes that should NOT be flagged as secrets
git checkout abcdef1234567890abcdef1234567890abcdef12
git cherry-pick abcdef1234567890abcdef1234567890abcdef12
git revert abcdef1234567890abcdef1234567890abcdef12
commit abcdef1234567890abcdef1234567890abcdef12
sha: abcdef1234567890abcdef1234567890abcdef12
