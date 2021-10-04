POSH-HPOneView
==============

HPE OneView makes it simple to deploy and manage today’s complex hybrid cloud infrastructure. HPE OneView can help you transform your data center to software-defined, and it supports HPE’s broad portfolio of servers, storage, and networking solutions, ensuring the simple and automated management of your hybrid infrastructure.  Software-defined intelligence enables a template-driven approach for deploying, provisioning, updating, and integrating compute, storage, and networking infrastructure.

This library enables PowerShell developers, IT automation engineers, or devops personel the ability to utilize HPE OneView's open REST API to automate infrastructure policies and operations.  Starting with the HPE OneView 5.00 PowerShell library, PowerShell Core is now supported.

The major changes are:

* Changing `HPOneView_Classes` class module from targeting DotNet Framework 4.6 to DotNet Standard 2.0.  This will require DotNet Framework 4.7.1 for Windows at a minimum, which means Windows 10 1709 or newer will be required.  It also means that Windows Management Framework 4.0 is no longer supported.
* Support Windows PowerShell 5.1 and 7.x for Windows, and PowerShellCore 7.x for Mac and Linux.
* Unified library for the supported PowerShell and PowerShellCore versions.
* Withe the deprecation of PowerShell 4.0, the EXE installer is also deprecated.  Microsoft provides built-in PowerShellGet support to save published modules from PowerShell Gallery, by using the [`Save-Module`](https://go.microsoft.com/fwlink/?LinkId=531351) Cmdlet.

## Build status

AppVeyor 6.30 Branch | AppVeyor 6.20 Branch | AppVeyor 6.10 Branch | AppVeyor 6.00 Branch
-------------------- | -------------------- | -------------------- | ---------------------
[![Build status][ovm-master-build-status-badge]][ov-master-status-link] [![PS Gallery][ovm-master-psgallery-badge]][ovm-master-psgallery-link] | [![Build status][ov-minus1-build-status-badge]][ov-minus1-build-link] [![PS Gallery][ov-minus1-psgallery-badge]][ov-minus1-psgallery-link] | [![Build status][ov-minus2-build-status-badge]][ov-minus2-build-link] [![PS Gallery][ov-minus2-psgallery-badge]][ov-minus2-psgallery-link] | [![Build status][ov-minus3-build-status-badge]][ov-minus3-build-link] [![PS Gallery][ov-minus3-psgallery-badge]][ov-minus3-psgallery-link]

## Getting started
To get started, use the [`Install-Module`](https://go.microsoft.com/fwlink/?LinkID=398573) Cmdlet to install from the PowerShell Gallery to your local system.

### For all supported PowerShell and PowerShellCore systems
```PowerShell
# Install library from the PowerShell Gallery
Install-Module HPEOneView.630

# Load the module
Import-Module HPEOneView.630

# Connect to your appliance
Connect-OVMgmt -Hostname MyAppliance.FQDN.Name -Credential $MyOneViewCredential
```

### Linux or Mac, including Windows Services for Linux (WSL)
Windows Services for Linux (WSL) is tested and supported using the Ubuntu 18.04 image from the [Windows Store](https://www.microsoft.com/en-us/p/ubuntu-1804-lts/9n9tngvndl3q?activetab=pivot:overviewtab).  To test and use WSL, Windows 10 1709 (aka Windows 10 Creaters Fall Update) is required.  Please see [this](https://docs.microsoft.com/en-us/windows/wsl/install-win10) Microsoft document for further instructions.

For Linux distributions and appliances with a CA signed/issued certificate, you will need to make sure the issuing CA, and CA chain, is exported to PEM format, and placed within the OS SSL cert trusts location.  For Ubuntu 18.04, you can:

1. Place the CA cert in PEM format (the cert format that starts with `-----BEGIN CERTIFICATE-----`) into `/usr/local/shared/ca-certificates`.
1. Execute `sudo update-ca-certificates` binary, which should look something like:
```bash
    chris@desktop2:~$ sudo update-ca-certificates
    Updating certificates in /etc/ssl/certs...
    1 added, 0 removed; done.
    Running hooks in /etc/ca-certificates/update.d...
    done.
```
3. If there are any additional cert errors and you simply want to test basic functionality, you can override certificate validation for the library using the following:
```powershell
# NOTE:  This is NOT supported in production as this is a security risk.
[HPEOneView.PKI.SslValidation]::IgnoreCertErrors = $true
```

## Known limitations
The library normally uses [FormatPX](https://github.com/KirkMunro/FormatPx) to fix formatting issues with the Microsoft provided core cmdlets Format-List and Format-Table.  However, FormatPX is not currently supported in PowerShellCore yet.  So, when attempting to use the default parameter set of `Get-OVNetwork`, which can return multiple network resource types, only the first network type will properly display.  The rest (like Fibre Channel or Fibre Channel over Ethernet) will display their full object properties.

The Get-OVCommandTrace Cmdlet will generate the required output.  But due to a limitation in the DotNet Standard API, a prior used API is no longer available, resulting in Verbose and Debug messages from the HPE OneView C# Class Library to not be captured.  When reporting errors, and using the Cmdlet, or if you invoke `[HPEOneView.Config]::EnableVerbose = $true` and/or `[HPEOneView.Config]::EnableDebug = $true`, the generated output should be recaptured by Select All, copy and then paste into the created log file.

## Getting help
First, [read the manual][ReadTheManualLink].  Cmdlets are documented here in a new doc repository.  The project wiki is no longer maintained, and will be removed in a future update.

Are you running into a road block?  Have an issue with unexpected bahriov?  Feel free to open a [![new issue][new-issue-badge-url]][new-issue-link] on the tracker.

You have a general question about the library?  For general questions, or need to discuss a topic that doesn't need to be tracked in the issue tracker, please join the new GitHub Discussions for the project: [![Join the discussion][github-chat-badge-url]][github-chat-link]

Still available, but not actively maintained Gitter.im chat room: [![Join the chat][gitter-chat-badge-url]][gitter-chat-link]

<!-- markdown variables links -->
[ReadTheManualLink]: https://hpe-docs.gitbook.io/posh-hpeoneview/
<!-- 6.30 -->
[ovm-master-build-status-badge]: https://ci.appveyor.com/api/projects/status/t0r1x79b9hnm328k?svg=true
[ov-master-status-link]: https://ci.appveyor.com/project/ChrisLynchHPE/posh-hpeoneview-il66a
[ovm-master-psgallery-badge]: https://img.shields.io/powershellgallery/dt/HPEOneView.630.svg?label=PSGallery
[ovm-master-psgallery-link]: https://www.powershellgallery.com/packages/HPEOneView.630
<!-- 6.20 -->
[ov-minus1-build-status-badge]: https://ci.appveyor.com/api/projects/status/cudbqf9lbnhyt4n3?svg=true
[ov-minus1-build-link]: https://ci.appveyor.com/project/ChrisLynchHPE/posh-hpeoneview-ynj1j
[ov-minus1-psgallery-badge]: https://img.shields.io/powershellgallery/dt/HPEOneView.620.svg?label=PSGallery
[ov-minus1-psgallery-link]: https://www.powershellgallery.com/packages/HPEOneView.620
<!-- 6.10 -->
[ov-minus2-build-status-badge]: https://ci.appveyor.com/api/projects/status/ew57ctqp89pj6vg3?svg=true
[ov-minus2-build-link]: https://ci.appveyor.com/project/ChrisLynchHPE/posh-hpeoneview-w8vk5
[ov-minus2-psgallery-badge]: https://img.shields.io/powershellgallery/dt/HPEOneView.610.svg?label=PSGallery
[ov-minus2-psgallery-link]: https://www.powershellgallery.com/packages/HPEOneView.610
<!-- 6.00 -->
[ov-minus3-build-status-badge]: https://ci.appveyor.com/api/projects/status/8cgu3yq8jruuhd3m?svg=true
[ov-minus3-build-link]: https://ci.appveyor.com/project/ChrisLynchHPE/posh-hponeview-ujl7m
[ov-minus3-psgallery-badge]: https://img.shields.io/powershellgallery/dt/HPOneView.600.svg?label=PSGallery
[ov-minus3-psgallery-link]: https://www.powershellgallery.com/packages/HPOneView.600

<!-- MISC DO NOT TOUCH -->
[new-issue-badge-url]: https://img.shields.io/badge/issues-new-yellowgreen?style=flat&logo=github
[new-issue-link]: https://github.com/HewlettPackard/POSH-HPOneView/issues/new/choose
[github-chat-badge-url]: https://img.shields.io/badge/chat-on%20github%20discussions-green?style=flat&logo=gitter
[github-chat-link]: https://github.com/HewlettPackard/POSH-HPEOneView/discussions
[gitter-chat-badge-url]: https://camo.githubusercontent.com/fd5dd4417d3bc721ada1bf5564e66e74de3cf909/68747470733a2f2f696d672e736869656c64732e696f2f7374617469632f76312e7376673f6c6162656c3d63686174266d6573736167653d6f6e25323067697474657226636f6c6f723d696e666f726d6174696f6e616c266c6f676f3d676974746572
[gitter-chat-link]: https://gitter.im/POSH-HPOneView/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge