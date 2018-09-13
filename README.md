
AppVeyor 3.10 Branch | AppVeyor 4.00 Branch | AppVeyor 4.10 Branch
-------------------- | -------------------- | ---------------------
[![Build status](https://ci.appveyor.com/api/projects/status/7aeeipw70yo0gbcm/branch/3.10?svg=true)](https://ci.appveyor.com/project/ChrisLynchHPE/posh-hponeview-34esg/branch/3.10) | [![Build status](https://ci.appveyor.com/api/projects/status/n4btdae2oaua0bra/branch/4.00?svg=true)](https://ci.appveyor.com/project/ChrisLynchHPE/posh-hponeview-cskif/branch/4.00) | [![Build status](https://ci.appveyor.com/api/projects/status/ubd52rrmholhuuwa/branch/4.10?svg=true)](https://ci.appveyor.com/project/ChrisLynchHPE/posh-hponeview-0fpb0/branch/4.10)


POSH-HPOneView
==============

This library provides a pure Windows PowerShell interface to the HPE OneView REST APIs.

 HPE OneView is a fresh approach to converged infrastructure management, inspired by the way you expect to work, with a single integrated view of your IT infrastructure.

 This PowerShell project is developed for those that want to automate tasks within HPE OneView or use PowerShell as a CLI for HPE OneView operations.

 ## Contributing and feature requests

The best way to directly collaborate with the project contributors is through GitHub: <https://github.com/HewlettPackard/oneview-python-samples>

* If you want to contribute to our code by either fixing a problem or creating a new feature, please open a GitHub pull request.
* If you want to raise an issue such as a defect, an enhancement request or a general issue, please open a GitHub issue.

Before you start to code, we recommend discussing your plans through a GitHub issue, especially for more ambitious contributions. This gives other contributors a chance to point you in the right direction, give you feedback on your design, and help you find out if someone else is working on the same thing.

Note that all patches from all contributors get reviewed.
After a pull request is made, other contributors will offer feedback. If the patch passes review, a maintainer will accept it with a comment.
When a pull request fails review, the author is expected to update the pull request to address the issue until it passes review and the pull request merges successfully.

At least one review from a maintainer is required for all patches.

### Developer's Certificate of Origin

All contributions must include acceptance of the DCO:

> Developer Certificate of Origin Version 1.1
>
> Copyright (C) 2004, 2006 The Linux Foundation and its contributors. 660
> York Street, Suite 102, San Francisco, CA 94110 USA
>
> Everyone is permitted to copy and distribute verbatim copies of this
> license document, but changing it is not allowed.
>
> Developer's Certificate of Origin 1.1
>
> By making a contribution to this project, I certify that:
>
> \(a) The contribution was created in whole or in part by me and I have
> the right to submit it under the open source license indicated in the
> file; or
>
> \(b) The contribution is based upon previous work that, to the best of my
> knowledge, is covered under an appropriate open source license and I
> have the right under that license to submit that work with
> modifications, whether created in whole or in part by me, under the same
> open source license (unless I am permitted to submit under a different
> license), as indicated in the file; or
>
> \(c) The contribution was provided directly to me by some other person
> who certified (a), (b) or (c) and I have not modified it.
>
> \(d) I understand and agree that this project and the contribution are
> public and that a record of the contribution (including all personal
> information I submit with it, including my sign-off) is maintained
> indefinitely and may be redistributed consistent with this project or
> the open source license(s) involved.

### Sign your work

To accept the DCO, simply add this line to each commit message with your
name and email address (git commit -s will do this for you):

    Signed-off-by: Jane Example <jane@example.com>

For legal reasons, no anonymous or pseudonymous contributions are
accepted.

## Submitting Code Pull Requests

We encourage and support contributions from the community. No fix is too
small. We strive to process all pull requests as soon as possible and
with constructive feedback. If your pull request is not accepted at
first, please try again after addressing the feedback you received.

To make a pull request you will need a GitHub account. For help, see
GitHub's documentation on forking and pull requests.

**Feature Requests:** If you have a need that is not met by the current implementation, please let us know (via a new issue).
This feedback is crucial for us to deliver a useful community experience. Do not assume that we have already thought of everything, because we assure you that is not the case.

## Naming convention

Please follow the scripting languages standard practices for naming conventions.  For instance, with PowerShell, please use approved Verbs Microsoft has defined.

## Testing

This repository is setup to perform regression testing using Appveyor CI pipeline.  This project utilizes the Pester testing framework for unit tests.  When submitting a Pull Request, 1 or more unit tests should be provided.  If one is not provided, the maintainers of the repository will assist in creating supporting unit tests.
