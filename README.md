# Introduction

This is a utility script to convert the json file produced by [Joern](https://joern.io)/[Ocular](https://www.shiftleft.io/ocular/) to [SARIF](https://sarifweb.azurewebsites.net/) format.

## Usage

```bash
sudo pip install joern2sarif
joern2sarif -i findings.json -o joern-findings.sarif
```

Example usage on [GitHub action](https://github.com/prabhu/explnode/blob/master/.github/workflows/ocular.yml)

## License

Apache 2.0
