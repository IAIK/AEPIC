# AEPIC Leak

This is the PoC implementation for the USENIX 2022 paper [**AEPIC Leak: Architecturally Leaking Uninitialized Data from the Microarchitecture**]() by [Pietro Borrello](https://pietroborrello.github.io), [Andreas Kogler](https://andreaskogler.com), [Martin Schwarzl](https://martinschwarzl.at/), [Moritz Lipp](https://mlq.me/), [Daniel Gruss](https://gruss.cc), and [Michael Schwarz](https://misc0110.net).

AEPIC Leak is the first architectural CPU bug that leaks stale data from the microarchitecture without using a side channel.
It architecturally leaks stale data incorrectly returned by reading undefined APIC-register ranges.

This README provides instruction on how to build and run the described attack.
The total install time should be around 30 minutes.

## 1. Dependencies

TODO Install Dependencies, e.g., g++ and libsgxstep
```bash
sudo apt install -y g++-11
```

Make sure that the machine is booted in xAPIC mode, by providing `nox2apic` in the Linux kernel command line.

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

## 4. Run APIC Dump

We provide a simple kernel module that dumps the content of the APIC MMIO region.
This confirms that the APIC leaks data on the machine tested.

```bash
$ cd src/apic_dump
$ make run
```

Running the `apic_dump` you will observe spurious memory returned by the APIC, as opposed to `0x00` bytes.

## 5. Run the experiments

...
