rekernelx-y := rekernelx_main.o rekernelx_genl.o rekernelx_netuid.o rekernelx_frozen.o rekernelx_binder.o rekernelx_signal.o rekernelx_netfilter.o rekernelx_binder_kp.o

obj-m += rekernelx.o

ifdef REKERNELX_VERSION
ccflags-y += -DREKERNELX_VERSION=\"$(REKERNELX_VERSION)\"
endif
