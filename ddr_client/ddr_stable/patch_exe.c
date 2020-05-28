#include "ddr.h"
#include "globals.h"

void __cdecl patch_eflag(app_pc instr_addr, P_EFLAG_PARA* pp) {
	void* drcontext;
	size_t instr_addr_fixed;
	byte* pc;

	drcontext = dr_get_current_drcontext();
	dr_mcontext_t mc = { sizeof(mc),DR_MC_ALL };
	dr_get_mcontext(drcontext, &mc);

	// Calculate the instr addr in file/IDA
	if (!OEP_moved_plus)
		instr_addr_fixed = (size_t)instr_addr + oep_diff;
	else
		instr_addr_fixed = (size_t)instr_addr - oep_diff;

	dr_printf("[DDR] [INFO] Toggling %s EFLAG at "PFX"\n", pp->patch_eflag_flag_str, instr_addr_fixed);
	print_disasm(drcontext, instr_addr, instr_addr_fixed);

	instr_t instr;
	instr_init(drcontext, &instr);
	instr_reset(drcontext, &instr);

	pc = decode(drcontext, instr_addr, &instr);
	if (pc == NULL) {
		dr_printf("[DDR] [ERROR] Invalid Instruction found! DynamoRIO can't decode instruction\n");
		dr_exit_process(1);
	}

	dr_printf("[DDR] [INFO] EFLAGS register before toggling: 0x%x\n", mc.xflags);
	if (mc.xflags & pp->patch_eflag_flag)
		dr_printf("[DDR] [INFO] %s EFLAG = 1\n", pp->patch_eflag_flag_str);
	else
		dr_printf("[DDR] [INFO] %s EFLAG = 0\n", pp->patch_eflag_flag_str);

	mc.xflags ^= pp->patch_eflag_flag;  // toggle eflag bit
	dr_set_mcontext(drcontext, &mc);

	dr_printf("[DDR] [INFO] EFLAGS register after toggling: 0x%x\n", mc.xflags);
	if (mc.xflags & pp->patch_eflag_flag)
		dr_printf("[DDR] [INFO] %s EFLAG set to 1\n", pp->patch_eflag_flag_str);
	else
		dr_printf("[DDR] [INFO] %s EFLAG set to 0\n", pp->patch_eflag_flag_str);

	instr_free(drcontext, &instr);
}

void __cdecl patch_sleep(app_pc instr_addr) {
	dr_messagebox("Execution stopped. Please click ok to proceed.");
}

