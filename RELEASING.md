# Releasing

Both packages are published by [.github/workflows/release.yml](.github/workflows/release.yml), from a signed tag
on `main`. No person and no repository secret holds a publish token. npm and PyPI each trust that one workflow
through OIDC (trusted publishing).

## Cutting a release

1. In a pull request:
   - set the version in `js/package.json` and `python/pyproject.toml`;
   - run `npm install --package-lock-only` in `js/`;
   - update EVOLUTION.md's rows.

   The `package` job in [test.yml](.github/workflows/test.yml) is the release's dry run. It runs
   `release/preflight.sh` and `release/build.sh`, and publishes nothing:
   - the preflight checks that the versions agree, that the claim set the release names (`varketa.vectors` in
     `js/package.json`) is in `claimSetVersions` with its vectors present, and that each package's `LICENSE` and
     `README.md` are the root's;
   - the build builds both packages (setuptools pinned by `release/build-constraints.txt`) and checks their contents.
2. Merge it. Tag the merge commit with a signed, annotated tag and push the tag:

   ```bash
   git tag -s vX.Y.Z <merge commit> -m "X.Y.Z"
   ```

   ```bash
   git push origin vX.Y.Z
   ```

3. The workflow runs:
   - `preflight`: `release/verify-tag.sh` (the tag is `vX.Y.Z`, annotated, signed with a signature GitHub verifies,
     and on `main`), then the preflight against the tag's version;
   - `test`: the test workflow on the tagged commit;
   - `build`: one build, uploaded as the run's `release-X.Y.Z` artifact;
   - `publish-npm` and `publish-pypi`: each in its own environment, from that artifact. A version a registry already
     holds is not published again, and `publish-npm` stops when it cannot tell whether npm holds the version;
   - `read-back`: `release/read-back.sh`, which requires each registry to serve exactly the artifact's bytes (npm's
     `dist.integrity`, and PyPI's file names and sha256s);
   - `notes`: the GitHub release for the tag. Its notes name the accepted claim-set versions, the vector set with its
     digest (`release/vectors-digest.sh`) and git tree, and `SHA256SUMS`; the artifacts are attached.

A failed job can be re-run. A re-run publishes nothing twice, and `read-back` judges what the registries hold.

## Owner setup, once

1. **Signing.** The person who tags adds their signing key (GPG or SSH) to their GitHub account, so GitHub verifies
   the tag.
2. **Tag ruleset.** Add a repository ruleset on tags matching `v*`: only maintainers may create them, and no one may
   update or delete them.
3. **Environments.** Create the `npm` and `pypi` environments under Settings → Environments, each with a deployment
   rule that allows tags `v*` and nothing else.
4. **PyPI.** Add a pending trusted publisher (pypi.org → Your account → Publishing):
   - project `varketa-verify-acting-principal`;
   - owner `Varketa`;
   - repository `verify-acting-principal`;
   - workflow `release.yml`;
   - environment `pypi`.

   The first tagged run creates the project.
5. **npm.** Create or confirm the `@varketa` organization on npmjs.com, with publish rights for the account that
   bootstraps (below). A trusted publisher is added from the package's settings page on npmjs.com. If the package does not
   exist yet, publish the first version once by hand from the workflow's own artifact:
   1. Push the first tag. `publish-npm` fails, `read-back` waits on it, and `publish-pypi` still publishes.
   2. Download the run's `release-X.Y.Z` artifact.
   3. `npm publish npm/varketa-verify-acting-principal-X.Y.Z.tgz --access public`, with an account that may publish
      to `@varketa` and its 2FA code.
   4. On the package's settings page, add the trusted publisher: GitHub Actions, organization `Varketa`, repository
      `verify-acting-principal`, workflow `release.yml`, environment `npm`. Then set publishing access to require
      two-factor authentication and disallow tokens.
   5. Re-run the failed jobs. `publish-npm` finds the version already published, and `read-back` checks it is the
      artifact's tarball.

   That first version carries no npm provenance. Every later one does.
