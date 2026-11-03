# Release process

A release starts when a version tag reachable from `main` is pushed.
[CHANGELOG.md](https://github.com/misiektoja/go-pki-scep/blob/main/CHANGELOG.md) has one section
per version. That section becomes the release description.

## Versioning

The module follows semantic versioning under the
[Compatibility policy](../reference/compatibility.md). Release tags are stable versions such as
`v0.1.0`. The release workflow refuses any other tag form.

## Steps

1. On `dev`, complete the section of the new version in `CHANGELOG.md` and date it on the release
   day.
2. Run the checks:

    ```bash
    make lint
    make test
    make docs-build
    VERSION=vX.Y.Z make release-check
    ```

    The release check exports `HEAD` with `git archive`, then verifies, builds, vets and tests the
    export and imports it from a separate module. It catches files that are untracked or only
    present locally. With `VERSION` set it also checks that the changelog has a dated heading for
    the version and no Unreleased section.

3. Merge `dev` into `main`, create a signed tag and push `main` and the tag:

    ```bash
    git tag -s vX.Y.Z -m 'vX.Y.Z'
    git push origin main vX.Y.Z
    ```

4. The release workflow checks that the tag belongs to the default branch, repeats the release
   check, builds source archives, an SBOM and checksums, attests their provenance and creates a
   **draft** release with the changelog section as its description. Review the draft and publish
   it.

Do not publish a release from the GitHub UI. Publishing creates the tag, which starts the workflow.
The workflow then refuses to rebuild a release that is already published. To recover, delete the
release and its tag with `gh release delete vX.Y.Z --cleanup-tag --yes` and push the tag again.
A draft that already exists for the tag is updated with the new assets and description. The
workflow can also be started by hand for an existing tag.

## Release assets

| Asset | Content |
| --- | --- |
| `go-pki-scep-vX.Y.Z-source.zip` and `.tar.gz` | The complete tagged source tree |
| `go-pki-scep-vX.Y.Z-sbom.cdx.json` | A CycloneDX software bill of materials |
| `go-pki-scep-vX.Y.Z_SHA256SUMS.txt` | SHA-256 checksums of the archives and the SBOM |
| `go-pki-scep-vX.Y.Z.intoto.jsonl` | The signed build provenance of the assets |
