# About

KRBTGS is a post-exploitation option for Cobalt Strike to retrieve a working TGT for the current user that Beacon is running as, or impersonating. The attack does not require the user's password, and only assumes that the user you are running as is within a domain-joined environment. It attempts to guess the encryption type by choosing the strongest to least strong. The resulting .ccache can be converted into KIRBI format to be imported into other Beacons, or passed to other toolsets such as Impacket's example scripts to perform your post-exploitation endeavours.

It is designed to work purely with Cobalt Strike through its 'Beacon Object File' format so that you can more easily play with Kerberos tooling without the need for external toolsets. This has been tested in a few different labs to ensure it works properly.

## Build

To build the 'Beacon Object File'  you will need mingw-w64 from musl.cc. Once you've installed the compilers within your PATH for x86_64 and i686, run `make`, which will build the BOF file to be used with Cobalt Strike.

Once you've build the corresponding KRBTGS BOF for their respective architectures, simply import the [KrbTgs.cna](KrbTgs.cna) script into your Aggressor script console. You're ready to start using it!

![](https://i.imgur.com/ExKZUD2.png)

Additionally, you will have to install impacket from the latest git repository. This is because the resulting output format returned from the toolset needs to be converted into a .CCACHE manually from a blob using [extract_ccache.py](https://github.com/SecIdiot/kit/tree/master/postex/krbtgs/scripts) script within the scripts directory.

```
$ pip install git+https://github.com/SecureAuthCorp/impacket.git
```

## Usage

