CONFIG_MODULE_SIG=n

# Удаляем KERNELDIR и PWD, они больше не нужны.
# Система сборки ядра сама найдет всё необходимое
# из переменных окружения, которые установит nix-shell.

# Эта переменная автоматически подхватит путь к ядру из окружения nix-shell
default-kernel-dir := /nix/store/cwpz9l6iy36c7gans1jhrp6qb4lhp8ha-linux-6.15.4-dev/lib/modules/6.15.4/build


ifeq ($(KERNELRELEASE),)
default:
	$(MAKE) -C $(default-kernel-dir) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(default-kernel-dir) M=$(CURDIR) clean
else

	pegasus-m += src/api_driver.o src/hook_packets.o src/pegasus_main.o src/storage_ip.o
	obj-m := pegasus.o
endif

