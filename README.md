# IoCCheck

Fast Golang program to check a bunch of IoCs against some TI providers. The program writes to the stdout just the identified ones.

## TI Platforms

So far, the following platforms have been integrated:
- AlienVault (apikey required, free)
- AbuseIP (apikey required, free)
- URLHaus
- MalwareBazaar

## Features

Some features already implemented are:
- IoC checks parallelization
- Multi-key support
- User configuration file

## Example usages

Read the IoCs from a file:

```bash
./ioccheck -f iocs.txt
```

Support for pipeline integration:

```bash
cat iocs.txt | ioccheck
```

All options:

```
./ioccheck --help
Usage of ./ioccheck:
  -f string
    	File with the IOCs
  -t int
    	Number of threads (default 10)
```

## Installation

Pretty easy actually, clone the repository and compile:

```bash
git clone https://github.com/cr4zyGoat/ioccheck.git
cd ioccheck
go build
```

Finally, modify the configuration file and copy this to the user configurations directory (~/.config/).

That's all, enjoy the tool ;)
