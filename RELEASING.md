# Release Process

## Versioning
The versioning follows the process described at [semver.org](https://semver.org/).

### Public API
We consider the public API of this project to be whatever is included in the
`LIBRARY_PUBLIC_HEADERS` defined in [src/CMakeLists.txt](src/CMakeLists.txt#L40). Currently, this includes
all the header files in `src/mococrw/`. Changes to these files will be versioned according
to versioning scheme described below.

## PRs & Releasing

### PR Checklist

What should be done with every PR (if no new release is created):
* [CHANGELOG](./CHANGELOG.md) is updated with the summary of the change (Unreleased section)
* If your change is going to break ABI (at the next release) please also put that into the [CHANGELOG](./CHANGELOG.md)
* CI testing against project specific CI systems

### Releasing Checklist

Check if the following steps have been performed **before** creating a new release. This includes
all kinds of releases (Major, Minor and Patch releases)
* [README](./README.md) is updated if necessary
* [CHANGELOG](./CHANGELOG.md) is updated (add the new release)
* Library soversion is increased in [src/CMakeLists.txt](src/CMakeLists.txt#L5) (major release only)

If all the steps above have been done you are good to go and create a new release:
* Create and push a signed tag [see here how to do that](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work)
  (make sure to increase the version number according to [semver.org](https://semver.org/))
* Use github UI to create a new release (using the signed tag you have created earlier)

### Release Frequency
We are developing this library based on our needs. That is, there is no regular releases schedule.
Instead we are going to create releases based on added functionality.

### Release Strategy:
In general, we will not create a new release for every PR. The following specifies what
kind of changes may be contained in which type of release.

* Patch-Releases x.y.(z+1) contain only:
  * API & ABI compatible bugfixes (e.g. vulnerabilities)
  * API & ABI compatible refactoring (e.g. refactoring of internal implementation)
* Minor-Releases x.(y+1).0 may contain:
  * New functionality that is API & ABI compatible
  * API & ABI comptaible refactoring of public API (e.g. deprecation of methods / functions)
* Major-Releases (x+1).0.0 may contain:
  * API & ABI breaking changes of any kind

