# Lib4VEX

Lib4VEX is a library to parse and generate VEX documents. It supports VEX documents created in the [OpenVEX](https://openvex.dev),
[CycloneDX](https://www.cyclonedx.org) or [CSAF](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) specifications.

It has been developed on the assumption that having a generic abstraction of vulnerability
regardless of the underlying format will be useful to developers.

The following facilities are provided:

- Generate OpenVEX, CycloneDX and CSAF VEX documents in JSON format
- Parse CycloneDX SBOM in JSON format and extract vulnerability information
- Parse OpenVEX and CSAF documents to extract vulnerability information
- Generated VEX document can be output to a file or to the console

## Installation

To install use the following command:

`pip install lib4vex`

Alternatively, just clone the repo and install dependencies using the following command:

`pip install -U -r requirements.txt`

The tool requires Python 3 (3.8+). It is recommended to use a virtual python environment especially
if you are using different versions of python. `virtualenv` is a tool for setting up virtual python environments which
allows you to have all the dependencies for the tool set up in a single environment, or have different environments set
up for testing using different versions of Python.

## API

### Metadata

### Product

### Vulnerability

### Debug

Creating the environment variable _**LIB4VEX_DEBUG**_ will result in some additional information being reported when a VEX document is being generated.

## Examples

A number of example scripts are included in the _examples_ subdirectory. Examples are provided for CSAF and CycloneDX scenarios.

## Tutorial

A tutorial showing a lifecycle of vulnerabilities is [available](TUTORIAL.md). Whilst the tutorial uses CSAF as the VEX document, equivalent
steps can be performed for producing a VEX document using CycloneDX.
						
## Implementation Notes

The following design decisions have been made in creating and processing VEX files:

1. VEXes should be produced with reference to an SBOM so that only vulnerabilities for components included in the SBOM are included in the VEX document.

2. The VEX document contains all reported vulnerabilities and the respective status. The latest VEX is indicated by the latest timestamp. The previous VEX documents are retained for audit purposes.

## Future Development

1. Complete OpenVEX support

2. Add support for SPDX Security profile when released as part of the SPDX 3.0 release.

## License

Licensed under the Apache 2.0 Licence.

## Limitations

This library is meant to support software development. The usefulness of the library is dependent on the data
which is provided. Unfortunately, the library is unable to determine the validity or completeness of such a VEX file; users of the library and
the resulting VEX file are therefore reminded that they should assert the quality of any data which is provided to the library.

## Feedback and Contributions

Bugs and feature requests can be made via GitHub Issues.
