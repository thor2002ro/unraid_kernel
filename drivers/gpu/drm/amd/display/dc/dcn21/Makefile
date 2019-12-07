# SPDX-License-Identifier: MIT
#
# Makefile for DCN21.

DCN21 = dcn21_init.o dcn21_hubp.o dcn21_hubbub.o dcn21_resource.o \
	 dcn21_hwseq.o dcn21_link_encoder.o

ifneq ($(call cc-option, -mpreferred-stack-boundary=4),)
	cc_stack_align := -mpreferred-stack-boundary=4
else ifneq ($(call cc-option, -mstack-alignment=16),)
	cc_stack_align := -mstack-alignment=16
endif

ifdef CONFIG_X86
CFLAGS_$(AMDDALPATH)/dc/dcn21/dcn21_resource.o := -mhard-float -msse $(cc_stack_align)

ifdef CONFIG_CC_IS_CLANG
CFLAGS_$(AMDDALPATH)/dc/dcn21/dcn21_resource.o += -msse2
endif
endif

ifdef CONFIG_PPC64
CFLAGS_$(AMDDALPATH)/dc/dcn21/dcn21_resource.o := -mhard-float -maltivec $(cc_stack_align)
endif

AMD_DAL_DCN21 = $(addprefix $(AMDDALPATH)/dc/dcn21/,$(DCN21))

AMD_DISPLAY_FILES += $(AMD_DAL_DCN21)
