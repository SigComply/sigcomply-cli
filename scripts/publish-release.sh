#!/usr/bin/env bash
# Pushes a release tag and publishes its GitHub prerelease. Used by the
# publish jobs of auto-release-pipeline.yml and release.yml.
#
#   publish-release.sh <tag> <asset>...
#
# Needs GITHUB_SHA (the commit to tag), GITHUB_REPOSITORY, a gh token in
# GH_TOKEN or GITHUB_TOKEN, and a checkout whose origin can take a tag push.
#
# Safe to re-run after a partial failure:
#   - the tag already on origin and pointing at GITHUB_SHA: not pushed again;
#   - the tag on origin pointing at any other commit: fails, never moves it;
#   - the release already exists: not created again; only assets it lacks
#     are uploaded, so an asset already published is never replaced;
#   - the release is a draft (gh release create uploads to a draft and
#     publishes it last; a job killed in between leaves one): its missing
#     assets are uploaded, then it is published, still as a prerelease.
#     With immutable releases nothing can be added after that.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <tag> <asset>..." >&2
  exit 2
fi
TAG=$1
shift
: "${GITHUB_SHA:?GITHUB_SHA must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

# 1. The tag. ls-remote exits 2 when nothing matches.
rc=0
remote=$(git ls-remote --exit-code origin "refs/tags/$TAG" "refs/tags/$TAG^{}") || rc=$?
case $rc in
  0)
    # An annotated tag lists its peeled commit as a second "^{}" line; a
    # lightweight tag has only the one line, already a commit.
    peeled=$(printf '%s\n' "$remote" | awk '$2 ~ /\^\{\}$/ {print $1}')
    if [ -z "$peeled" ]; then
      peeled=$(printf '%s\n' "$remote" | awk 'NR == 1 {print $1}')
    fi
    if [ "$peeled" != "$GITHUB_SHA" ]; then
      echo "::error::Tag $TAG already exists on origin at $peeled, not at $GITHUB_SHA. Refusing to publish; pick another version or delete the stray tag."
      exit 1
    fi
    echo "Tag $TAG already on origin at $GITHUB_SHA; not pushing it again."
    ;;
  2)
    git config user.name "github-actions[bot]"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
    # -f: replace a local tag the checkout may carry; origin has none.
    git tag -f -a "$TAG" -m "Release $TAG" "$GITHUB_SHA"
    git push origin "refs/tags/$TAG"
    echo "Pushed tag $TAG at $GITHUB_SHA."
    ;;
  *)
    echo "::error::git ls-remote failed (exit $rc) while looking up $TAG."
    exit 1
    ;;
esac

# 2. The release, as a prerelease: releases/latest moves only when
# release-promote.yml promotes it.
if existing=$(gh release view "$TAG" --repo "$GITHUB_REPOSITORY" --json assets --jq '.assets[].name' 2>/dev/null); then
  missing=()
  for asset in "$@"; do
    if ! printf '%s\n' "$existing" | grep -qxF "$(basename "$asset")"; then
      missing+=("$asset")
    fi
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    echo "Release $TAG already exists with every asset; not creating it again."
  else
    echo "Release $TAG already exists; uploading ${#missing[@]} missing asset(s)."
    gh release upload "$TAG" --repo "$GITHUB_REPOSITORY" "${missing[@]}"
  fi
  if [ "$(gh release view "$TAG" --repo "$GITHUB_REPOSITORY" --json isDraft --jq .isDraft)" = "true" ]; then
    gh release edit "$TAG" --repo "$GITHUB_REPOSITORY" --draft=false
    echo "Published the draft of $TAG as a prerelease."
  fi
else
  gh release create "$TAG" \
    --repo "$GITHUB_REPOSITORY" \
    --title "SigComply CLI $TAG" \
    --generate-notes \
    --prerelease \
    --verify-tag \
    "$@"
  echo "Published $TAG as a prerelease."
fi
