# AEPIC Leak

This is the PoC implementation for the USENIX 2022 paper [**AEPIC Leak: Architecturally Leaking Uninitialized Data from the Microarchitecture**]() by [Pietro Borrello](https://pietroborrello.github.io), [Andreas Kogler](https://andreaskogler.com), [Martin Schwarzl](https://martinschwarzl.at/), [Moritz Lipp](https://mlq.me/), [Daniel Gruss](https://gruss.cc), and [Michael Schwarz](https://misc0110.net).

AEPIC Leak is the first architectural CPU bug that leaks stale data from the microarchitecture without using a side channel.
It architecturally leaks stale data incorrectly returned by reading undefined APIC-register ranges.

This README provides instruction on how to build and run the described attack.
The total install time should be around 30 minutes.

## 0. Jumpstart: Run APIC Dump

We provide a simple kernel module that dumps the content of the APIC MMIO region.
This confirms that the APIC leaks data on the machine tested.

```bash
$ cd src/apic_dump
$ make run
```

If your CPU is vulnerable, running the `apic_dump` you will observe spurious memory returned by the APIC, as opposed to `0x00` bytes.

**NOTE:**
Make sure that the machine is booted in xAPIC mode, by providing `nox2apic` in the Linux kernel command line.

## 1. Dependencies

```bash
sudo apt install -y g++-11
```

build sgx-step SDK and library
```bash
git submodule init
cd sgx-step
cd sdk/intel-sdk/ && ./install_SGX_SDK.sh && source /opt/intel/sgxsdk/environment
cd libsgxstep && make && cd ..
```

## 2. Build

This step builds the Custom SGX Driver and the attack PoCs.

```bash
$ cd src
$ make
```

## 3. Load the Custom SGX Driver

```bash
$ cd src
$ make load
```

## 4. Run the experiments

### Victim Enclaves

Victim runner to experiment:
* aes: to leak Intel IPPC AES
* egetkey: to leak seal key
* memory: to leak simple memory content
* rdrand: to leak rdrand content
* rsa: to leak rsa private key
* simple_ssa: to leak SSA region

### Enclave Runner

Runs a victim enclave and waits for user input to terminate it:
```bash
cd src/runner
./runner ../enclaves/aes/enclave.signed.so
```

### Enclave Dumper

Dumps the whole memory of an enclave by exploiting AEPIC Leak.
Usage: `./dumper [enclave_pid] [enclave_idx] [flags] [dump_file]`
where flags: `x=dump_code d=dump_data p=non_present s=show r=readable`

E.g.,
```bash
./dumper `pidof runner` 0 dsr <output_file>
```

### Enclave Stepper

Single steps an enclave until the required instruction, and then dumps the target registers by dumping the SSA page using AEPIC Leak.
```bash
sudo ./stepper <path_to_enclave> <print_readable> <path_to_config>
```

We use a configuration file to tell the stepper when to stop and what to dump. E.g. `src/enclaves/aes/stepper_config`.
