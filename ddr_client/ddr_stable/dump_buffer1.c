#include "ddr.h"
#include "globals.h"

reg_t dumpbuf_size = 0;
reg_t dumpbuf_addr = 0;

void my_call_pre_wrapper(void* wrapcxt, OUT void** user_data) {

	size_t func_addr_fixed;
	size_t retval = 0x666;
	dr_mcontext_t* mc = drwrap_get_mcontext(wrapcxt);
	app_pc wrapped_func = drwrap_get_func(wrapcxt);

	pa_call_para = pa_call_para_start;
	while (pa_call_para) {

		if (!OEP_moved_plus)
			func_addr_fixed = pa_call_para->patch_call_func_PC - oep_diff;
		else
			func_addr_fixed = pa_call_para->patch_call_func_PC + oep_diff;

		if (func_addr_fixed == (size_t) wrapped_func) {
			retval = pa_call_para->patch_call_ret;
		}
		pa_call_para = pa_call_para->nextcp;
	}
	pa_call_para = pa_call_para_start;

	drwrap_skip_call(wrapcxt, (void*)retval, 0);

	dr_printf("[DDR] [INFO] Wrapped function "PFX" called from "PFX".\n", wrapped_func, mc->pc);
	dr_printf("[DDR] [INFO] Return value set to "PFX"(signed decimal:%d)(unsigned decimal:%u)\n", retval, retval, retval);
}

int __cdecl get_mem_addr_dump_buffer(void* drcontext, reg_t* memaddr, char Optype, char OptypePtrType, int Opnum, app_pc instr_addr, dr_mcontext_t mc) {
	byte* pc;
	opnd_t opnd;
	reg_id_t reg;
	instr_t instr;
	instr_init(drcontext, &instr);
	instr_reset(drcontext, &instr);
	pc = decode(drcontext, instr_addr, &instr); // fill in instr
	opnd = instr_get_src(&instr, Opnum);
	*memaddr = 0;

	// Source operant
	if (tolower(Optype) == 's') {
		dr_printf("[DDR] [INFO] Getting buffer address from source operant %d.\n", Opnum);
		// op is register
		if (my_opnd_is_reg(opnd)) {
			reg = opnd_get_reg(opnd);
			*memaddr = reg_get_value(reg, &mc);
			//dr_printf("[DDR] [DEBUG] inst_mem_addr_reg: "PFX"\n", *memaddr);
		}
		else if (opnd_is_immed(opnd)) {
			*memaddr = opnd_get_immed_int(opnd);
			//dr_printf("[DDR] [DEBUG] inst_mem_addr_immed: "PFX"\n", *memaddr);
		}
		// op is not a register
		else {
			*memaddr = (reg_t)my_opnd_compute_address(opnd, &mc);
			//dr_printf("[DDR] [DEBUG] inst_mem_addr_noreg: "PFX"\n", *memaddr);
		}
	}
	// Destination operant
	else if (tolower(Optype) == 'd') {
		dr_printf("[DDR] [INFO] Getting buffer address from destination operant %d.\n", Opnum);

		opnd = instr_get_dst(&instr, Opnum);

		// op is register
		if (my_opnd_is_reg(opnd)) {
			reg = opnd_get_reg(opnd);
			*memaddr = reg_get_value(reg, &mc);
			//dr_printf("[DDR] [INFO] inst_mem_addr_reg: "PFX"\n", *memaddr);
		}
		else if (opnd_is_immed(opnd)) {
			*memaddr = opnd_get_immed_int(opnd);
			//dr_printf("[DDR] [INFO] inst_mem_addr_immed: "PFX"\n", *memaddr);
		}
		// op is not a register
		else {
			*memaddr = (reg_t)my_opnd_compute_address(opnd, &mc);
			//dr_printf("[DDR] [INFO] inst_mem_addr_noreg: "PFX"\n", *memaddr);
		}
	}
	instr_free(drcontext, &instr);

	return (memaddr != 0) ? TRUE : FALSE;
}

int __cdecl get_op_size_dump_buffer(void* drcontext, reg_t* memaddr, char Optype, char OptypePtrType, int Opnum, app_pc instr_addr, dr_mcontext_t mc) {
	byte* pc;
	opnd_t opnd;
	reg_id_t reg;
	instr_t instr;
	instr_init(drcontext, &instr);
	instr_reset(drcontext, &instr);
	pc = decode(drcontext, instr_addr, &instr); // fill in instr
	opnd = instr_get_src(&instr, Opnum);
	*memaddr = 0;

	// Source operant
	if (tolower(Optype) == 's') {
		dr_printf("[DDR] [INFO] Getting buffer size from source operant %d.\n", Opnum);
		// op is register
		if (my_opnd_is_reg(opnd)) {
			reg = opnd_get_reg(opnd);
			*memaddr = (reg_t)reg_get_value(reg, &mc);
			//dr_printf("[DDR] [INFO] inst_mem_addr_reg: "PFX"\n", *memaddr);
		}
		// op is an immediate value
		else if (opnd_is_immed(opnd)) {
			*memaddr = (reg_t)opnd_get_immed_int(opnd);
			//dr_printf("[DDR] [INFO] inst_mem_addr_immed: "PFX"\n", *memaddr);
		}
		// op is not a register
		else {
			*memaddr = (reg_t)my_opnd_compute_address(opnd, &mc);
			//dr_printf("[DDR] [INFO] inst_mem_addr_noreg: "PFX"\n", *memaddr);
		}
	}
	// Destination operant
	else if (tolower(Optype) == 'd') {
		dr_printf("[DDR] [INFO] Getting buffer size from destination operant %d.\n", Opnum);

		opnd = instr_get_dst(&instr, Opnum);

		// op is register
		if (my_opnd_is_reg(opnd)) {
			reg = opnd_get_reg(opnd);
			*memaddr = reg_get_value(reg, &mc);
			//dr_printf("[DDR] [INFO] inst_mem_addr_reg: "PFX"\n", *memaddr);
		}
		// op is an immediate value
		else if (opnd_is_immed(opnd)) {
			*memaddr = opnd_get_immed_int(opnd);
			//dr_printf("[DDR] [INFO] inst_mem_addr_immed: "PFX"\n", *memaddr);
		}
		else {
			*memaddr = (reg_t)my_opnd_compute_address(opnd, &mc);
			//dr_printf("[DDR] [INFO] inst_mem_addr_noreg: "PFX"\n", *memaddr);
		}
	}
	instr_free(drcontext, &instr);

	return (memaddr != 0) ? TRUE : FALSE;
}

void event_thread_init_global(void* drcontext)
{
	app_pc FileEntryPoint, PEEntryPoint, PEImagebase;
	module_data_t* app;

	char* samplename;
	char samplename_cleaned[MAX_PATH * 2];
	byte* peb;

	size_t func_addr_fixed;
	static thread_id_t last_threat_id;

	thread_id = dr_get_thread_id(drcontext);
	process_id = dr_get_process_id();
	dr_printf("[DDR] [INFO] New Threat initalization started. Process ID = %u Threat ID = %u\n", process_id, thread_id);

	if (last_threat_id != 0) {
		dr_printf("[DDR] [WARNING] This is not the first thread. Multithreaded is not supported, but works in many cases.\n");

		if (patch_call_set) {

			pa_call_para = pa_call_para_start;

			while (pa_call_para) {

				if (!OEP_moved_plus)
					func_addr_fixed = pa_call_para->patch_call_func_PC - oep_diff;
				else
					func_addr_fixed = pa_call_para->patch_call_func_PC + oep_diff;

				drwrap_wrap((app_pc)func_addr_fixed, my_call_pre_wrapper, NULL);
				dr_printf("[DDR] [INFO] Function at "PFX" wrapped and return value set to "PFX"\n", func_addr_fixed, pa_call_para->patch_call_ret);
				pa_call_para = pa_call_para->nextcp;
			}

			pa_call_para = pa_call_para_start;
		}
		return;
	}
	else {
		first_thread_id = thread_id;
		dr_printf("[DDR] [INFO] First thread. Setting main thread id to %d\n", first_thread_id);
	}

	// Get sample filename  
	app = dr_get_main_module();
	samplename = app->full_path;
	if (strlen(samplename) > MAX_PATH) {
		dr_printf("[DDR] [ERROR] Filename path too long\n");
		dr_exit_process(1);
	}
	else {
		memcpy(samplename_cleaned, samplename, strlen(samplename));
		samplename_cleaned[strlen(samplename)] = '\0';
	}
	dr_printf("[DDR] [INFO] Samplename: %s.\n", samplename_cleaned);

	// Get PEB
	peb = dr_get_app_PEB();

	// Get Imagebase and EP from PE in memory
	PEEntryPoint = app->entry_point;
	PEImagebase = app->start;

	// Get EP from orginal file on disk like IDA sees it
	if (!getOEPfromPEfile(samplename, &FileEntryPoint)) {
		dr_printf("[DDR] [WARNING] OEP not found in file.\n");
		FileEntryPoint = PEEntryPoint;
	}

	// Calculate the offset if the loader moved it
	if (FileEntryPoint >= PEEntryPoint) {
		oep_diff = FileEntryPoint - PEEntryPoint;
	}
	else {
		oep_diff = PEEntryPoint - FileEntryPoint;
		OEP_moved_plus = TRUE;
	}

	dr_printf("[DDR] [INFO] PEB            : "PFX"\n", peb);
	dr_printf("[DDR] [INFO] PE Imagebase   : "PFX"\n", PEImagebase);
	dr_printf("[DDR] [INFO] PE EP          : "PFX"\n", PEEntryPoint);
	dr_printf("[DDR] [INFO] File EP        : "PFX"\n", FileEntryPoint);
	dr_printf("[DDR] [INFO] EP diff        : "PFX"\n", oep_diff);

	dr_free_module_data(app);

	if (patch_call_set) {

		pa_call_para = pa_call_para_start;
		
		while (pa_call_para) {

			if (!OEP_moved_plus)
				func_addr_fixed = pa_call_para->patch_call_func_PC - oep_diff;
			else
				func_addr_fixed = pa_call_para->patch_call_func_PC + oep_diff;

			drwrap_wrap((app_pc) func_addr_fixed, my_call_pre_wrapper, NULL);
			dr_printf("[DDR] [INFO] Function at "PFX" wrapped and return value set to "PFX"\n", func_addr_fixed, pa_call_para->patch_call_ret);
			pa_call_para = pa_call_para->nextcp;
		}

		pa_call_para = pa_call_para_start;
	}

	last_threat_id = thread_id;
}

void __cdecl process_instr_size_dump_buffer(app_pc instr_addr, S_DUMP_PARA* dp) {

	size_t instr_addr_fixed;
	void* drcontext;
	int ret;

	drcontext = dr_get_current_drcontext();
	dr_mcontext_t mc = { sizeof(mc),DR_MC_ALL };
	dr_get_mcontext(drcontext, &mc);

	// Calculate the instr addr in file/IDA
	if (!OEP_moved_plus)
		instr_addr_fixed = (size_t)instr_addr + oep_diff;
	else
		instr_addr_fixed = (size_t)instr_addr - oep_diff;

	// Disasm instruction at PC
	print_disasm(drcontext, instr_addr, instr_addr_fixed);

	// Get size of buffer in operator
	ret = get_op_size_dump_buffer(drcontext, &dumpbuf_size, dp->sizeOptype, dp->sizeOptypePtrType, dp->sizeOpnum, instr_addr, mc);

	if (ret) {
		dr_printf("[DDR] [INFO] buffer size = "PFX" (%d)\n", dumpbuf_size, dumpbuf_size);
		dumbuf_SizeFound = TRUE;
	}
	else {
		dr_printf("[DDR] [ERROR] Getting buffer size failed\n", dumpbuf_size);
		dr_exit_process(1);
	}
}

void __cdecl process_instr_addr_dump_buffer(app_pc instr_addr, S_DUMP_PARA* dp) {

	size_t instr_addr_fixed;
	void* drcontext;
	int ret;

	drcontext = dr_get_current_drcontext();
	dr_mcontext_t mc = { sizeof(mc),DR_MC_ALL };
	dr_get_mcontext(drcontext, &mc);

	// Calculate the instr addr in file/IDA
	if (!OEP_moved_plus)
		instr_addr_fixed = (size_t)instr_addr + oep_diff;
	else
		instr_addr_fixed = (size_t)instr_addr - oep_diff;

	// Disasm instruction at PC
	print_disasm(drcontext, instr_addr, instr_addr_fixed);

	// Get memory address of buffer in operator
	ret = get_mem_addr_dump_buffer(drcontext, &dumpbuf_addr, dp->bufferOptype, dp->bufferOptypePtrType, dp->bufferOpnum, instr_addr, mc);

	if (ret) {
		dr_printf("[DDR] [INFO] buffer address = "PFX"\n", dumpbuf_addr);
		dumpbuf_AddrFound = TRUE;
	}
	else {
		dr_printf("[DDR] [ERROR] Getting buffer address failed\n");
		dr_exit_process(1);
	}
}

void __cdecl process_instr_dump_buffer(app_pc instr_addr, S_DUMP_PARA* dp) {

	size_t bytesread;
	char* bytesbuf;
	void* drcontext;
	size_t instr_addr_fixed;

	file_t dump_fp = dr_open_file(dp->filename, DR_FILE_WRITE_OVERWRITE);
	if (dump_fp == INVALID_FILE) {
		dr_printf("[DDR] [ERROR] Can't create dump file. Does the directory you specified exist?\n");
		dr_exit_process(1);
	}

	drcontext = dr_get_current_drcontext();

	// Calculate the instr addr in file/IDA
	if (!OEP_moved_plus)
		instr_addr_fixed = (size_t)instr_addr + oep_diff;
	else
		instr_addr_fixed = (size_t)instr_addr - oep_diff;

	// Print disasm at instr_addr
	print_disasm(drcontext, instr_addr, instr_addr_fixed);

	bytesbuf = (char*) dr_global_alloc(sizeof(char) * dumpbuf_size);

	// Safe memory buffer to file
	if (dr_safe_read((app_pc)dumpbuf_addr, (size_t) dumpbuf_size, bytesbuf, &bytesread)) {

		if (bytesread == dumpbuf_size) {
			dr_write_file(dump_fp, bytesbuf, dumpbuf_size);
			dr_close_file(dump_fp);
			dr_printf("[DDR] [INFO] [FINAL] Done. Written %d bytes from address "PFX" to file: %s.\n", dumpbuf_size, dumpbuf_addr, dp->filename);
		}
		else {
			dr_printf("[DDR] [ERROR] [FINAL] Data not written to file. Bytes read: %d.\n", bytesread);
		}
	}
	dr_global_free(bytesbuf, sizeof(char) * dumpbuf_size);
}
