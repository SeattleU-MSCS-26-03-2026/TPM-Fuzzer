# Seeds

Seeds are corpus entries used to guide the fuzzer during its initial runs in order
to have more targeted and closely guided mutations. The TPM Fuzzer utilizes dedicated tooling
to generate the seed corpus fed into each supported target (Structured vs Unstructured).

## Quick Start

Although the seed corpus used by the fuzz targets provided in this repository is usually committed to source control, we do encourage regenerating the seed corpus occasionally to ensure the serialized structures still match our definitions. To do so, a convenient script is provided:

```sh
./scripts/generate-seeds.sh
```

To learn more about how the seed generation tooling works and how to get started using it, see the [Seed Generation README](../tools/seed-generation/README.md).
