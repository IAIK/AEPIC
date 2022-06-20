all:
	@make -C apic_dump
	@make -C enclaves
	@make -C runner
	@make -C stepper
	@make -C dumper
	@make -C debug_dumper

load:
	@make -C linux-sgx-driver load

clean:
	@make -C enclaves clean
	@make -C runner clean
	@make -C stepper clean
	@make -C dumper clean
	@make -C linux-sgx-driver clean