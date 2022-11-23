## How to cut a new stable release

Stable releases are tagged from the `uwsgi-2.0` branch. Changes to the `uwsgi-2.0` branch are
cherry-picked from the `master` branch.

Before tagging a new release the release notes should be updated and a file named
`Changelog-2.0.XY.rst` where XY is the number of the release created in
the [uwsgi-docs repository](https://github.com/unbit/uwsgi-docs). The file should then be referenced
the newly created changelog file from the `index.rst`.

In order to cut a new release you have to first bump the version and then tag with the same version
the last commit in git. All the commands are assumed to be run from the `uwsgi-2.0` branch.

The the tag should be pushed to git and the source distribution created with the following commands.
Please remember to substitute XY with proper version.

```
git tag 2.0.XY
git push ---tags origin HEAD
git archive HEAD --prefix uwsgi-2.0.XY/ -o uwsgi-2.0.XY.tar.gz
```

Then the tarball must be uploaded to pypi with:

```
python3 -m twine upload uwsgi-2.0.XY.tar.gz
```
