obj-y += rijndael.o
obj-y += vmac.o
obj-$(CONFIG_PAYLOAD_SIGNING) += builtin_payload_key.o

ifeq ($(CONFIG_PAYLOAD_SIGNING),y)
key_path := $(srctree)/crypto/$(patsubst "%",%,$(CONFIG_PAYLOAD_SIG_KEY))
$(obj)/builtin_payload_key.bin: $(key_path) $(srctree)/tools/extract-key.py
	$(srctree)/tools/extract-key.py < $< > $@.new
	$(call move-if-changed,$@.new,$@)

$(obj)/builtin_payload_key.S: $(srctree)/tools/binfile $(obj)/builtin_payload_key.bin FORCE
	$(call if_changed,binfile,$(obj)/builtin_payload_key.bin xen_livepatch_key_data)
endif
