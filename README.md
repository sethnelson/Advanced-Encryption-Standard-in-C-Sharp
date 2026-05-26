# Advanced-Encryption-Standard-in-C-Sharp
This is a C# implementation of the AES algorithm based on FIPS 197 as available through NIST.

## Important Security Disclaimer
This implementation is for portfolio purposes only. It is **not intended for production** cryptographic use. Always use established cryptographic libraries for real-world uses.

## Technical Summary
The implementation includes:
- Fast (bitwise) add and multiply functions
- All functions described in FIPS 197
- Additional helper functions to manage and inspect the block state
- FIPS 197 test parameters supplied in main

## Project's Purpose
This project was completed as part of applied cryptography coursework to better understand the primitives that support secure communication and modern security architecture.

## How to Run
1. Navigate to the AES directory in shell
2. Call 'dotnet run' from the command line
3. The test cases available in the main function will execute
Note: this project was built with .NET 9.0.109. You may need to update your .NET to make the program compile.

## What I Learned
- How AES organizes data into state matrices
- How substitution and permutation provide diffusion/confusion
- How to implement software based on a set of technical specifications
