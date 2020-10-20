/* This file handles the CmdOpt_NormalTrace */

#include "ddr.h"
#include "globals.h"

void event_module_load_trace_instr(void* drcontext, const module_data_t* info, bool loaded)
{
#ifdef _DEBUG
	dr_printf("[DDR] [DEBUG] event_module_load_trace_instr module loaded: %s:\n", dr_module_preferred_name(info));
#endif
	if (lib_is_not_blacklisted_trace_instr(info))
		iterate_exports_trace_instr(info);
}

process_id_t getFirstPIDfromFile(char* pidsfilename) {

	file_t fPidsfile;
	uint max_retries;
	process_id_t pid = 0;
	size_t bytes_read;
	char data[MAX_PATH + 20];
	char* sPid;
	size_t sPidLen=0;
	
	for (max_retries = 0; max_retries < 3; max_retries++) {
		dr_printf("[DDR] [INFO] Trying to open PID file: %s\n", pidsfilename);
		fPidsfile = dr_open_file(pidsfilename, DR_FILE_READ); // write PID to PIDs file
		if (fPidsfile == INVALID_FILE) {
			dr_printf("[DDR] [ERROR] Failed to open initial process log file: %s. Attempt number: %u\n", pidsfilename, max_retries);
			Sleep(300);
			continue;
		}
		break;
	}

	bytes_read = dr_read_file(fPidsfile, data, MAX_PATH + 10);
	data[bytes_read] = '\0';
	sPid = getSubstr(data, "[", "]");
	sPidLen = strlen(sPid);
	pid = (process_id_t) strtoull(sPid, NULL, 10);
	
	dr_close_file(fPidsfile);

	dr_global_free(sPid, strlen(sPid)+1);
	return pid;

}

void event_thread_init_trace_instr(void* drcontext)
{
#ifdef _DEBUG
	dr_printf("\n[DDR] [DEBUG] event_thread_init_trace_instr start.\n");
#endif

	app_pc FileEntryPoint, PEEntryPoint, PEImagebase;
	module_data_t* app;

	char* samplename;
	char samplename_cleaned[MAX_PATH * 2];
	const char *app_name;
	byte* peb;
	static thread_id_t last_threat_id;
	size_t func_addr_fixed;
	
	thread_counter = thread_counter + 1;
	thread_id  = dr_get_thread_id(drcontext);
	process_id = dr_get_process_id();
	app_name   = dr_get_application_name();
	dr_printf("[DDR] [INFO] New thread initialization started. Appname = %s Process ID = %u Threat ID = %u Thread counter = %u\n", 
		app_name, process_id, thread_id, thread_counter);

	// is this first thread of the process ?
	if (pListThreads == NULL) {
		// ---- New process, first threat. ----
		dr_printf("[DDR] [INFO] New process, first thread started.\n");

		// allocate memory for threads linked list (pListThreads)
		pListThreads = (S_PROCS*)dr_global_alloc(sizeof(S_PROCS));
		pListThreads_start = pListThreads;

#ifdef _DEBUG
		dr_printf("[DDR] [DEBUG] [MEMOP] allocated memory for main thread. Memaddr: "PFX" thread_id=%d process_id=%u\n", 
			pListThreads, thread_id, process_id);
#endif
		// create process-thread log file	
		if (global_pidThreadsFullFilename == NULL) {
			global_pidThreadsFullFilename = (char*)dr_global_alloc(MAX_PATH);
		}

		dr_snprintf(global_pidThreadsFullFilename, MAX_PATH, "%s\\%s_%s_%u.txt", global_logpath, global_pidThreadsFilename, app_name, dr_get_process_id());
		dr_printf("[DDR] [INFO] writing thread info to: %s\n", global_pidThreadsFullFilename);

		global_fPidThreads = dr_open_file(global_pidThreadsFullFilename, DR_FILE_WRITE_OVERWRITE); // write PID to PIDs file
		if (global_fPidThreads == INVALID_FILE) {
			dr_printf("[DDR] [ERROR] Failed to open individual threads log file: %s\n", global_pidThreadsFullFilename);
		}
		dr_global_free(global_pidThreadsFullFilename, MAX_PATH);

		dr_fprintf(global_fPidThreads, "%s [%u] [%u]\r\n", app_name, process_id, thread_id);

		// fill process structure
		// is this the first process ?
		if (*processids == process_id) {
			pListThreads->start_process_id = process_id;
		}
		else {
			pListThreads->start_process_id = *processids;
		}
		pListThreads->prevproc = NULL;
		pListThreads->process_id = process_id;
		pListThreads->threat_id = thread_id;
		pListThreads->nextproc = NULL;
	}
	else {
		// ---- Existing process 2nd to n thread  ----
		dr_printf("[DDR] [INFO] Existing process. New thread started.\n");

		if (global_logpath) {
			debug_print("Using log path %s\n", global_logpath);
		}
		else {
			dr_printf("[DDR] [ERROR] [%s:%d] global logpath file not found\n", __FILE__, __LINE__);
		}

		// log process/thread info to process-thread file	
		dr_fprintf(global_fPidThreads, "%s [%u] [%u]\r\n", app_name, process_id, thread_id);
		
		pListThreads->nextproc = (S_PROCS*)dr_global_alloc(sizeof(S_PROCS));
#ifdef _DEBUG
		dr_printf("[DDR] [DEBUG] [MEMOP] allocated memory for sub thread. Memaddr: "PFX" thread_id=%d process_id=%u\n",
			pListThreads->nextproc, thread_id, process_id);
#endif
		pListThreads->nextproc->prevproc = pListThreads;
		pListThreads = pListThreads->nextproc;

		// is this the first process ?
		if (*processids == process_id) {
			pListThreads->start_process_id = process_id;
		}
		else {
			pListThreads->start_process_id = *processids;
		}
		pListThreads->process_id = process_id;
		pListThreads->threat_id = thread_id;
		pListThreads->nextproc = NULL;
	}

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

	// Get sample Filename  
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

	// Escape filename string for JSON file
	if (!escape_dir_str(samplename_cleaned)) {
		dr_printf("[DDR] [ERROR] Failed to escape file path\n");
		dr_exit_process(1);
	}

	// Write meta data about the sample into the logfile
	// TBD: use a proper JSON lib instead
	dr_fprintf(global_trace_fp, "{\n\"samplename\"             : \"%s\",\n", samplename_cleaned ? samplename_cleaned : "FILENAME_PARSING_ERROR");

#ifdef X86_64
	dr_fprintf(global_trace_fp, "\"architecture\"           : \"x64\",\n");
#else
	dr_fprintf(global_trace_fp, "\"architecture\"           : \"x32\",\n");
#endif

	dr_fprintf(global_trace_fp, "\"trace_start\"            : \""PFX"\",\n", from_addr);
	dr_fprintf(global_trace_fp, "\"trace_end\"              : \""PFX"\",\n", to_addr);
	dr_fprintf(global_trace_fp, "\"num_instr_to_trace\"     : \"%d\",\n", inst_count);

	// Get PEB
	peb = dr_get_app_PEB();

	PEEntryPoint = app->entry_point;
	PEImagebase = app->start;

	// get OEP from orginal file on disk
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

	dr_fprintf(global_trace_fp, "\"peb\"                    : \""PFX"\",\n", peb);
	dr_fprintf(global_trace_fp, "\"imagebase\"              : \""PFX"\",\n", PEImagebase);
	dr_fprintf(global_trace_fp, "\"entrypoint\"             : \""PFX"\",\n", PEEntryPoint);
	dr_fprintf(global_trace_fp, "\"oep\"                    : \""PFX"\",\n", FileEntryPoint);
	dr_fprintf(global_trace_fp, "\"oep_diff\"               : \""PFX"\",\n", oep_diff);
	dr_fprintf(global_trace_fp, "\"break_addr\"             : \""PFX"\",\n", break_addr ? break_addr : 0);
	dr_fprintf(global_trace_fp, "\"instruction\"            : \n[\n");

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

	//last_threat_id = thread_id;
	last_threat_id = dr_get_thread_id(drcontext);

	dr_free_module_data(app);

#ifdef _DEBUG
	dr_printf("\n[DDR] [DEBUG] event_thread_init_trace_instr end.\n");
#endif
}

void event_thread_exit_trace_instr(void* drcontext)
{
	//S_TRACE_PARA* trace_para_prev;
	S_PROCS* pListThreads_tmp;

#ifdef _DEBUG
	dr_printf("\n[DDR] [DEBUG] event_thread_exit_trace_instr start.\n");
	dr_printf("[DDR] [DEBUG] Thread counter: %u\n", thread_counter);
#endif

	if (first_thread_id == dr_get_thread_id(drcontext)) {

		dr_printf("[DDR] [INFO] Main thread (id = %d) was terminated.\n", first_thread_id);
		dr_close_file(global_fPidThreads);

		// Fix trace file
		dr_fprintf(global_trace_fp, " ]\n}\n");
		dr_close_file(global_trace_fp);

		dr_printf("[DDR] [INFO] Fixing trace file: %s\n", global_trace_LogFilename);
		fix_comma_in_jsonfile(global_trace_LogFilename);
		dr_printf("[DDR] [INFO] Trace file fixed.\n");
		
		// Fix API trace file
		dr_file_seek(global_trace_api_fp, -2, DR_SEEK_CUR);
		dr_fprintf(global_trace_api_fp, "\n ]\n}\n");
		dr_close_file(global_trace_api_fp);
		
		dr_printf("[DDR] [INFO] Fixing API trace file: %s\n", global_trace_ApiLogfilename);
		fix_comma_in_jsonfile(global_trace_ApiLogfilename);
		dr_printf("[DDR] [INFO] API trace file fixed.\n");

		dr_global_free(global_trace_LogFilename, MAX_PATH);
		dr_global_free(global_trace_ApiLogfilename, MAX_PATH);

		/*if (trace_para_set) {
			trace_para = trace_para_start;
			while (trace_para) {
				dr_global_free(trace_para->filename, MAX_FILE_LINE_LEN);
				trace_para_prev = trace_para;
				trace_para = trace_para->nexttr;
				dr_global_free(trace_para_prev, sizeof(S_TRACE_PARA));
			}
		}*/

		SYSTEMTIME lt;
		GetLocalTime(&lt);
		dr_printf("[DDR] [INFO] Time : %02d:%02d:%02d:%d\n", lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
	}
	else {
		dr_printf("[DDR] [INFO] Thread with id %d was terminated\n", dr_get_thread_id(drcontext));
	}

	// Is this the last living thread ? Free the linked list
	if (thread_counter == 1) {
#ifdef _DEBUG
		dr_printf("[DDR] [DEBUG] [MEMOP] Last living thread (thread_id = %d proccess = %u) reached. Free'ing memory.\n", 
			dr_get_thread_id(drcontext), dr_get_process_id());
#endif
		pListThreads = pListThreads_start;
		while (pListThreads) {
			pListThreads_tmp = pListThreads->nextproc;
#ifdef _DEBUG
			dr_printf("[DDR] [DEBUG] [MEMOP] free'ing memory: "PFX" thread_id = %d\n", pListThreads, pListThreads->threat_id);
#endif
			dr_global_free(pListThreads, sizeof(S_PROCS));
			pListThreads = pListThreads_tmp;
		}
#ifdef _DEBUG
		dr_printf("[DDR] [DEBUG] [MEMOP] process memory free'ed.\n");
#endif
	}
	thread_counter = thread_counter - 1;


#ifdef _DEBUG
	dr_printf("\n[DDR] [DEBUG] event_thread_exit_trace_instr end.\n");
#endif
}


void __cdecl process_instr_trace_instr_new(app_pc instr_addr, S_TRACE_PARA* tr) 
{
	char* cf_bit = "cf=0";
	char* pf_bit = "pf=0";
	char* af_bit = "af=0";
	char* zf_bit = "zf=0";
	char* sf_bit = "sf=0";
	char* df_bit = "df=0";
	char* of_bit = "of=0";

	size_t instr_addr_fixed;

	void* drcontext;
	byte* pc;

	drcontext = dr_get_current_drcontext();
	dr_mcontext_t mc = { sizeof(mc),DR_MC_ALL };
	dr_get_mcontext(drcontext, &mc);

	if (!OEP_moved_plus)
		instr_addr_fixed = (size_t)instr_addr + oep_diff;
	else
		instr_addr_fixed = (size_t)instr_addr - oep_diff;

	if (instr_addr_fixed == tr->breakaddress) {
		event_thread_exit_trace_instr(dr_get_current_drcontext());
		dr_abort();  // does not call any exit routines, just kills the process
	}

	if (tr->max_instr <= 0) {
		dr_printf("[DDR] [WARNING] Max. number of instructions reached. Logging stopped at 0x%x.\n", instr_addr);
		dr_exit_process(0);  // calls exit routines
	}

#ifdef _DEBUG
	if (dbgLevel >= 5) {
		dr_printf("[DDR] [DEBUG] i:0x%x\n", instr_addr_fixed);
	}
	/*
	if (instr_addr_fixed == 0x401924) {
		dr_printf("[DDR] [DEBUG] -------- Create access violation when process instruction 0x401924. -----------\n");
		memcpy(NULL, 0xffffffff, 50); // create access violation
	}
	*/
#endif

	if ((instr_addr_fixed >= tr->start) && (instr_addr_fixed <= tr->end)) {

		instr_t instr;

		if (first_thread_id == dr_get_thread_id(drcontext)) {
			// light trace 
			if (tr->light_trace_only) {
				dr_fprintf(global_trace_fp, "  {\n  \"instr_num\" : \"%d\",\n", inst_num++);
				// medium trace preparation: TBD add a medium trace option to config
				if (true) {
					instr_init(drcontext, &instr);
					instr_reset(drcontext, &instr);
					dr_fprintf(global_trace_fp, "  \"address\" : \""PFX"\",\n", instr_addr_fixed);
					pc = decode(drcontext, instr_addr, &instr);

					size_t disasm_buf_size = 254;
					unsigned char* disasm_buf = (unsigned char*)dr_global_alloc(sizeof(unsigned char) * disasm_buf_size);
					instr_disassemble_to_buffer(dr_get_current_drcontext(), &instr, disasm_buf, disasm_buf_size);
					dr_fprintf(global_trace_fp, "  \"disasm\"  : \"%s\",\n", disasm_buf);
					dr_global_free(disasm_buf, sizeof(unsigned char) * disasm_buf_size);

					log_instr_opnds_trace_instr(global_trace_fp, &instr, &mc, drcontext, 16);
					instr_free(drcontext, &instr);
				}
				else {
					dr_fprintf(global_trace_fp, "  \"address\" : \""PFX"\"\n", instr_addr_fixed);
				}
				dr_fprintf(global_trace_fp, " },\n");
				tr->max_instr--;	
			}
			// full trace
			else {
				instr_init(drcontext, &instr);
				instr_reset(drcontext, &instr);

				tr->max_instr--;

				pc = decode(drcontext, instr_addr, &instr);
				if (pc == NULL) {
					dr_fprintf(global_trace_fp, "ERROR: Invalid Instruction found! DynamoRIO can't decode instruction\n");
					return;
				}

				// get flags and registers
				ref_flags = mc.xflags;

				if (EFLAGS_CF & ref_flags) cf_bit = "cf=1";
				if (EFLAGS_PF & ref_flags) pf_bit = "pf=1";
				if (EFLAGS_AF & ref_flags) af_bit = "af=1";
				if (EFLAGS_ZF & ref_flags) zf_bit = "zf=1";
				if (EFLAGS_SF & ref_flags) sf_bit = "sf=1";
				if (EFLAGS_DF & ref_flags) df_bit = "df=1";
				if (EFLAGS_OF & ref_flags) of_bit = "of=1";

				if (first_instr_set)
					first_instr_set = FALSE;
				else
					dr_fprintf(global_trace_fp, ",\n");

				dr_fprintf(global_trace_fp, " {\n");
				dr_fprintf(global_trace_fp, "  \"instr_num\" : \"%d\",\n", inst_num++);
				dr_fprintf(global_trace_fp, "  \"address\" : \""PFX"\",\n", instr_addr_fixed);
				dr_fprintf(global_trace_fp, "  \"xax\"     : \""PFX"\",\n", mc.xax);
				log_mem_at_reg_trace_instr((app_pc)mc.xax, "xax", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"xbx\"     : \""PFX"\",\n", mc.xbx);
				log_mem_at_reg_trace_instr((app_pc)mc.xbx, "xbx", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"xcx\"     : \""PFX"\",\n", mc.xcx);
				log_mem_at_reg_trace_instr((app_pc)mc.xcx, "xcx", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"xdx\"     : \""PFX"\",\n", mc.xdx);
				log_mem_at_reg_trace_instr((app_pc)mc.xdx, "xdx", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"xsp\"     : \""PFX"\",\n", mc.xsp);
				log_mem_at_reg_trace_instr((app_pc)mc.xsp, "xsp", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"xbp\"     : \""PFX"\",\n", mc.xbp);
				log_mem_at_reg_trace_instr((app_pc)mc.xbp, "xbp", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"xsi\"     : \""PFX"\",\n", mc.xsi);
				log_mem_at_reg_trace_instr((app_pc)mc.xsi, "xsi", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"xdi\"     : \""PFX"\",\n", mc.xdi);
				log_mem_at_reg_trace_instr((app_pc)mc.xdi, "xdi", global_trace_fp);

#ifdef X86_64
				dr_fprintf(global_trace_fp, "  \"r8\"      : \""PFX"\",\n", mc.r8);
				log_mem_at_reg_trace_instr((app_pc)mc.r8, "r8", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"r9\"      : \""PFX"\",\n", mc.r9);
				log_mem_at_reg_trace_instr((app_pc)mc.r9, "r9", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"r10\"     : \""PFX"\",\n", mc.r10);
				log_mem_at_reg_trace_instr((app_pc)mc.r10, "r10", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"r11\"     : \""PFX"\",\n", mc.r11);
				log_mem_at_reg_trace_instr((app_pc)mc.r11, "r11", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"r12\"     : \""PFX"\",\n", mc.r12);
				log_mem_at_reg_trace_instr((app_pc)mc.r12, "r12", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"r13\"     : \""PFX"\",\n", mc.r13);
				log_mem_at_reg_trace_instr((app_pc)mc.r13, "r13", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"r14\"     : \""PFX"\",\n", mc.r14);
				log_mem_at_reg_trace_instr((app_pc)mc.r14, "r14", global_trace_fp);
				dr_fprintf(global_trace_fp, "  \"r15\"     : \""PFX"\",\n", mc.r15);
				log_mem_at_reg_trace_instr((app_pc)mc.r15, "r15", global_trace_fp);
#endif

				dr_fprintf(global_trace_fp, "  \"eflags\"  : \"0x%x\",\n", ref_flags);
				dr_fprintf(global_trace_fp, "  \"cf_bit\"  : \"%s\",\n", cf_bit);
				dr_fprintf(global_trace_fp, "  \"pf_bit\"  : \"%s\",\n", pf_bit);
				dr_fprintf(global_trace_fp, "  \"af_bit\"  : \"%s\",\n", af_bit);
				dr_fprintf(global_trace_fp, "  \"zf_bit\"  : \"%s\",\n", zf_bit);
				dr_fprintf(global_trace_fp, "  \"sf_bit\"  : \"%s\",\n", sf_bit);
				dr_fprintf(global_trace_fp, "  \"df_bit\"  : \"%s\",\n", df_bit);
				dr_fprintf(global_trace_fp, "  \"of_bit\"  : \"%s\",\n", of_bit);

				// Print DISASM of instruction to JSON file 
				size_t disasm_buf_size = 254;
				unsigned char* disasm_buf = (unsigned char*)dr_global_alloc(sizeof(unsigned char) * disasm_buf_size);
				instr_disassemble_to_buffer(dr_get_current_drcontext(), &instr, disasm_buf, disasm_buf_size);
				dr_fprintf(global_trace_fp, "  \"disasm\"  : \"%s\",\n", disasm_buf);
				dr_global_free(disasm_buf, sizeof(unsigned char)* disasm_buf_size);

				log_instr_opnds_trace_instr(global_trace_fp, &instr, &mc, drcontext, 16);
				dr_fprintf(global_trace_fp, "\n");
				dr_fprintf(global_trace_fp, " }");

				instr_free(drcontext, &instr);
			}
		}
	}
}

static void iterate_exports_trace_instr(const module_data_t* info)
{
	dr_symbol_export_iterator_t* exp_iter =
		dr_symbol_export_iterator_start(info->handle);
	while (dr_symbol_export_iterator_hasnext(exp_iter)) {
		dr_symbol_export_t* sym = dr_symbol_export_iterator_next(exp_iter);
		if ((sym->is_code) && (sym->addr != NULL)) {
			dr_fprintf(global_trace_api_fp, "  {\"address\"    : \""PFX"\",\n", sym->addr);
			dr_fprintf(global_trace_api_fp, "   \"name\"       : \"%s\",\n", sym->name);
			dr_fprintf(global_trace_api_fp, "   \"module\"     : \"%s\"},\n", dr_module_preferred_name(info));
		}
	}
	dr_symbol_export_iterator_stop(exp_iter);
}

static bool lib_is_not_blacklisted_trace_instr(const module_data_t* info) {

	char* blacklist[] = { "dynamorio.dll", "drmgr.dll", "ddr.dll", NULL };
	int i = 0;
	while (blacklist[i]) {
		if (strstr(dr_module_preferred_name(info), blacklist[i++]) != NULL)
			return FALSE;
	}
	return TRUE;
}

static unsigned char* get_byte_string_trace_instr(unsigned char* bytesbuf, size_t bytesread, size_t *resultstr_size) {

	if (bytesread < 1) return NULL;

	unsigned int i;
	unsigned char* bytestr = (unsigned char*)dr_global_alloc(sizeof(unsigned char) * (bytesread * 3 + 1));
	unsigned char* bytestr_tmp = bytestr;
	unsigned char c;
	for (i = 0; i < bytesread; i++) {
		c = *(bytesbuf + i);
		dr_snprintf(bytestr_tmp, 4, "%02x ", c);
		bytestr_tmp += 3;
	}
	unsigned char* charstr = (unsigned char*)dr_global_alloc(sizeof(unsigned char) * (bytesread + 1));
	unsigned char* charstr_tmp = charstr;
	for (i = 0; i < bytesread; i++) {
		c = *(bytesbuf + i);
		if ((c < 127) && (c > 31) && (c != 92) && (c != 34)) // exclude '\'=92 and "=34 for JSON comp. 
			dr_snprintf(charstr_tmp++, 2, "%c", c);
		else
			dr_snprintf(charstr_tmp++, 2, ".");
	}

	*resultstr_size = strlen(bytestr) + strlen(charstr) + 3 + 1; //3 spaces in snprintf below
	unsigned char* resultstr = (unsigned char*)dr_global_alloc(sizeof(unsigned char) * (*resultstr_size));
	if (resultstr) {
		dr_snprintf(resultstr, *resultstr_size, "%s   %s", bytestr, charstr);

		dr_global_free(bytestr, sizeof(unsigned char) * (bytesread * 3 + 1));
		dr_global_free(charstr, sizeof(unsigned char) * (bytesread + 1));

		return resultstr;
	}
	else {
		dr_printf("[DDR] [ERROR] Failed to allocate memory in get_byte_string_trace_instr.\n");
		dr_exit_process(1);
	}
	return NULL;
}

static void log_bytestream_trace_instr(file_t f, unsigned char* bytesbuf, size_t bytesread, app_pc memaddr, uint instr_mem_size) {

	size_t resultstr_size;

	char* bytesstr = get_byte_string_trace_instr(bytesbuf, bytesread, &resultstr_size);

	if (bytesstr) {
		dr_fprintf(f, "  \"inst_mem_addr\"  : \""PFX"\",\n", memaddr);
		dr_fprintf(f, "  \"inst_mem_size\"  : \""PFX"\",\n", instr_mem_size);
		dr_fprintf(f, "  \"inst_mem_data\"  : \"%s\",\n", bytesstr);
		dr_global_free(bytesstr, resultstr_size);
	}
	else {
		dr_fprintf(f, "  \"inst_mem_addr\"  : \""PFX"\",\n", memaddr);
		dr_fprintf(f, "  \"inst_mem_size\"  : \""PFX"\",\n", instr_mem_size);
		dr_fprintf(f, "  \"inst_mem_data\"  : \"NOT_DECODED\",\n");
	}
}

static bool write_mem_data_trace_instr(file_t f, size_t numbytes, app_pc memaddr, char* json_field_str) {
	char* bytesbuf, * bytesstr;
	size_t bytesread;
	size_t resultstr_size;

	bytesbuf = (char*)dr_global_alloc(sizeof(char) * numbytes);
	if (bytesbuf) {
		dr_safe_read(memaddr, numbytes, bytesbuf, &bytesread);

		bytesstr = get_byte_string_trace_instr(bytesbuf, bytesread, &resultstr_size);
		if (bytesstr) {
			// only add to JSON file if not NULL
			dr_fprintf(f, ",\n");
			dr_fprintf(f, "  \"%s\"  : \"%s\"", json_field_str, bytesstr);
			dr_global_free(bytesstr, resultstr_size);
			dr_global_free(bytesbuf, sizeof(char) * numbytes);
			return TRUE;
		}
		else {
			dr_global_free(bytesbuf, sizeof(char) * numbytes);
			return FALSE;
		}
	}
	else {
		dr_printf("[DDR] [ERROR] Failed to allocate memory in write_mem_data_trace_instr.");
		dr_exit_process(1);
	}
	return FALSE;
}

static bool write_mem_to_file_trace_instr(file_t f, ssize_t numbytes, app_pc memaddr) {
	char* bytesbuf;
	ssize_t bytesread;
	ssize_t byteswritten;

	bytesbuf = (char*)dr_global_alloc(sizeof(char) * numbytes);
	dr_safe_read(memaddr, numbytes, bytesbuf, &bytesread);
	dr_printf("[DDR] [INFO] Bytes read: %d\n", bytesread);

	byteswritten = dr_write_file(f, bytesbuf, numbytes);
	dr_printf("[DDR] [INFO] Bytes written: %d\n", byteswritten);

	if (bytesbuf) {
		dr_global_free(bytesbuf, sizeof(char) * numbytes);
		return FALSE;
	}
}

static void write_src_op_to_logfile_trace_instr(file_t f, instr_t* instr, app_pc memaddr_src0, size_t bytesread, size_t numbytes) {

	size_t memaddr_src0_ptr;

	dr_fprintf(f, "  \"inst_mem_addr_src0\"  : \""PFX"\"", memaddr_src0);
	write_mem_data_trace_instr(f, numbytes, memaddr_src0, "inst_mem_addr_src0_data");
	dr_safe_read(memaddr_src0, sizeof(size_t), &memaddr_src0_ptr, &bytesread);
	dr_fprintf(f, ",\n  \"inst_mem_addr_src0_data_ptr\"  : \""PFX"\"", memaddr_src0_ptr);
	write_mem_data_trace_instr(f, numbytes, (app_pc)memaddr_src0_ptr, "inst_mem_addr_src0_data_ptr_data");

}

static void log_instr_opnds_trace_instr(file_t f, instr_t* instr, dr_mcontext_t* mc, void* drcontext, size_t numbytes) {

	int    num_dsts = 0, num_srcs = 0;
	opnd_t opnd_src0, opnd_dst0;
	app_pc memaddr_src0, memaddr_dst0;
	size_t memaddr_src0_ptr, memaddr_dst0_ptr;
	size_t bytesread = 0;
	reg_id_t reg;

	num_dsts = instr_num_dsts(instr);
	num_srcs = instr_num_srcs(instr);

	// --- handle memory access of special instructions --- : 

	// direct call
	if (instr_is_call_direct(instr)) {

		opnd_src0 = instr_get_src(instr, 0);

		if (my_opnd_is_reg(opnd_src0)) {
			reg = opnd_get_reg(opnd_src0);
			memaddr_src0 = (app_pc)reg_get_value(reg, mc);
		}
		else {
			memaddr_src0 = opnd_get_pc(opnd_src0);
		}
		write_src_op_to_logfile_trace_instr(f, instr, memaddr_src0, bytesread, numbytes);
		return;
	}
	// indirect call
	if (instr_is_call_indirect(instr)) {

		opnd_src0 = instr_get_src(instr, 0);
		if (my_opnd_is_reg(opnd_src0)) {
			reg = opnd_get_reg(opnd_src0);
			memaddr_src0 = (app_pc)reg_get_value(reg, mc);
		}
		else {
			memaddr_src0 = my_opnd_compute_address(opnd_src0, mc);
		}
		write_src_op_to_logfile_trace_instr(f, instr, memaddr_src0, bytesread, numbytes);
		return;
	}

	// ret
	if (instr_is_return(instr)) {

		opnd_src0 = instr_get_src(instr, 0);
		if (my_opnd_is_reg(opnd_src0)) {
			reg = opnd_get_reg(opnd_src0);
			memaddr_src0 = (app_pc)reg_get_value(reg, mc);
			write_src_op_to_logfile_trace_instr(f, instr, memaddr_src0, bytesread, numbytes);
		}

		if (opnd_is_immed(opnd_src0)) {
			memaddr_src0 = (app_pc) opnd_get_immed_int(opnd_src0);
			write_src_op_to_logfile_trace_instr(f, instr, memaddr_src0, bytesread, numbytes);
		}

		return;
	}

	// unconditional direct branch (jmp, etc)
	if (instr_is_ubr(instr)) {

		opnd_src0 = instr_get_src(instr, 0);
		memaddr_src0 = opnd_get_pc(opnd_src0);
		write_src_op_to_logfile_trace_instr(f, instr, memaddr_src0, bytesread, numbytes);
		return;
	}

	// conditional branch
	if (instr_is_cbr(instr)) {
		if (light_trace_only) {
			// skip if jump is not taken
			if (!instr_jcc_taken(instr, mc->xflags)) {
				dr_file_seek(f, -2, DR_SEEK_CUR);
				dr_fprintf(f, "\n");
				return;
			}
		}
		opnd_src0 = instr_get_src(instr, 0);
		memaddr_src0 = opnd_get_pc(opnd_src0);
		write_src_op_to_logfile_trace_instr(f, instr, memaddr_src0, bytesread, numbytes);
		return;
	}

	// Don't log anything further if light_trace_only is set
	if (light_trace_only) {
		// Delete last comma
		dr_file_seek(f, -2, DR_SEEK_CUR);
		dr_fprintf(f, "\n");
		return;
	}

	// push
	if (instr_get_opcode(instr) == OP_push || instr_get_opcode(instr) == OP_push_imm) {
		opnd_src0 = instr_get_src(instr, 0);

		// operant is register
		if (my_opnd_is_reg(opnd_src0)) {
			reg = opnd_get_reg(opnd_src0);
			memaddr_src0 = (app_pc)reg_get_value(reg, mc);  //TBD check typecast
			write_src_op_to_logfile_trace_instr(f, instr, memaddr_src0, bytesread, numbytes);
			return;
		}
		// anyhing else
		else {
			memaddr_src0 = my_opnd_compute_address(opnd_src0, mc);
			write_src_op_to_logfile_trace_instr(f, instr, memaddr_src0, bytesread, numbytes);
			return;
		}
	}

	// CMP
	if (instr_get_opcode(instr) == OP_cmp) {
		dr_fprintf(f, "  \"inst_mem_instr_opname_cmp\"  : \"%s\",\n", decode_opcode_name(instr_get_opcode(instr)));

		opnd_src0 = instr_get_src(instr, 0);
		opnd_dst0 = instr_get_src(instr, 1);

		// src operant is register
		if (my_opnd_is_reg(opnd_src0)) {
			reg = opnd_get_reg(opnd_src0);
			memaddr_src0 = (app_pc)reg_get_value(reg, mc);  //TBD check typecast
			dr_fprintf(f, "  \"inst_mem_addr_src0\"     : \""PFX"\"", memaddr_src0);
			write_mem_data_trace_instr(f, numbytes, memaddr_src0, "inst_mem_addr_src0_data");
			dr_fprintf(f, ",\n");
		}
		// src operant is anyhing else
		else {
			memaddr_src0 = my_opnd_compute_address(opnd_src0, mc);
			dr_fprintf(f, "  \"inst_mem_addr_src0\"     : \""PFX"\"", memaddr_src0);
			write_mem_data_trace_instr(f, numbytes, memaddr_src0, "inst_mem_addr_src0_data");
			dr_fprintf(f, ",\n");
		}

		// dst operant is register
		if (my_opnd_is_reg(opnd_dst0)) {
			reg = opnd_get_reg(opnd_dst0);
			memaddr_dst0 = (app_pc)reg_get_value(reg, mc);  //TBD check typecast
			dr_fprintf(f, "  \"inst_mem_addr_dst0\"     : \""PFX"\"", memaddr_dst0);
			write_mem_data_trace_instr(f, numbytes, memaddr_dst0, "inst_mem_addr_dst0_data");
			return;
		}
		// dst operant is anyhing else
		else {
			memaddr_dst0 = my_opnd_compute_address(opnd_dst0, mc);
			dr_fprintf(f, "  \"inst_mem_addr_dst0\"     : \""PFX"\"", memaddr_dst0);
			write_mem_data_trace_instr(f, numbytes, memaddr_dst0, "inst_mem_addr_dst0_data");
			return;
		}
	}

	// --- handle all other instructions --- :
	if (((num_dsts > 0) && (num_dsts < MAX_NUM_DSTS_OP)) || (num_srcs > 0) && (num_dsts < MAX_NUM_SRCS_OP))
		dr_fprintf(f, "  \"inst_mem_instr_opname\"  : \"%s\",\n", decode_opcode_name(instr_get_opcode(instr)));
	else
		dr_fprintf(f, "  \"inst_mem_instr_opname\"  : \"%s\"", decode_opcode_name(instr_get_opcode(instr)));

	// destination operant
	if ((num_dsts > 0) && (num_dsts < MAX_NUM_DSTS_OP)) {  // '&& num_dsts < 3' covers dynamoRio bug

		opnd_dst0 = instr_get_dst(instr, 0);

		// op is register
		if (my_opnd_is_reg(opnd_dst0)) {
			reg = opnd_get_reg(opnd_dst0);
			memaddr_dst0 = (app_pc)reg_get_value(reg, mc);
			dr_fprintf(f, "  \"inst_mem_addr_dst0\"  : \""PFX"\"", memaddr_dst0);
			write_mem_data_trace_instr(f, numbytes, memaddr_dst0, "inst_mem_addr_dst0_data");
		}
		// op is not a register
		else {
			memaddr_dst0 = my_opnd_compute_address(opnd_dst0, mc);
			dr_fprintf(f, "  \"inst_mem_addr_dst0\"  : \""PFX"\"", memaddr_dst0);
			write_mem_data_trace_instr(f, numbytes, memaddr_dst0, "inst_mem_addr_dst0_data");
		}

		// the op is a memory reference
		if (opnd_is_memory_reference(opnd_dst0)) {
			dr_fprintf(f, ",\n");
			dr_safe_read(memaddr_dst0, sizeof(size_t), &memaddr_dst0_ptr, &bytesread);
			dr_fprintf(f, "  \"inst_mem_addr_dst0_data_ptr\"  : \""PFX"\"", memaddr_dst0_ptr);
			write_mem_data_trace_instr(f, numbytes, (app_pc)memaddr_dst0_ptr, "inst_mem_addr_dst0_data_ptr_data");
		}

	}
	// source operant
	if ((num_srcs > 0) && (num_dsts < MAX_NUM_SRCS_OP)) { // '&& num_dsts < 3' covers dynamoRio bug
		if ((num_dsts > 0) && (num_dsts < MAX_NUM_DSTS_OP))
			dr_fprintf(f, ",\n");

		opnd_src0 = instr_get_src(instr, 0);

		// op is register
		if (my_opnd_is_reg(opnd_src0)) {
			reg = opnd_get_reg(opnd_src0);
			memaddr_src0 = (app_pc)reg_get_value(reg, mc);
			dr_fprintf(f, "  \"inst_mem_addr_src0\"  : \""PFX"\"", memaddr_src0);
			write_mem_data_trace_instr(f, numbytes, memaddr_src0, "inst_mem_addr_src0_data");
		}
		// op is not a register
		else {
			memaddr_src0 = my_opnd_compute_address(opnd_src0, mc);
			dr_fprintf(f, "  \"inst_mem_addr_src0\"  : \""PFX"\"", memaddr_src0);
			write_mem_data_trace_instr(f, numbytes, memaddr_src0, "inst_mem_addr_src0_data");
		}

		// the op is a memory reference
		if (opnd_is_memory_reference(opnd_src0)) {
			dr_fprintf(f, ",\n");
			dr_safe_read(memaddr_src0, sizeof(size_t), &memaddr_src0_ptr, &bytesread);
			dr_fprintf(f, "  \"inst_mem_addr_src0_data_ptr\"  : \""PFX"\"", memaddr_src0_ptr);
			write_mem_data_trace_instr(f, numbytes, (app_pc)memaddr_src0_ptr, "inst_mem_addr_src0_data_ptr_data");
		}

		// --- Code for detecting an DynamoRIO bug with instr_t init ---
		if (num_dsts > MAX_NUM_DSTS_OP - 1) {
			dr_fprintf(f, "!! -- fail -- !!"); // break JSON format to generate error in IDA plugin, remove if you don't want this
			dr_fprintf(f, ",\n");
			dr_fprintf(f, "  \"inst_mem_addr_dst0_fail\"  : \"DR_BUG_DETECTED\",\n");
			dr_fprintf(f, "  \"inst_mem_addr_dst0_num_dsts\"  : \"%d\"", num_dsts);
			num_dsts = 0;
		}
		if (num_srcs > MAX_NUM_SRCS_OP - 1) {
			dr_fprintf(f, "!! -- fail -- !!"); // break JSON format to generate error in IDA plugin, remove if you don't want this
			dr_fprintf(f, ",\n");
			dr_fprintf(f, ",\n");
			dr_fprintf(f, "  \"inst_mem_addr_src0_fail\"  : \"DR_BUG_DETECTED\",\n");
			dr_fprintf(f, "  \"inst_mem_addr_src0_num_srcs\"  : \"%d\"", num_srcs);
			num_srcs = 0;
		}
		// --- End ---

		// --- Maybe used in a future feature ---
		/*
		if (opnd_is_abs_addr(opnd_src0))
		dr_fprintf(f, "  \"opnd_is_abs_addr\"  : \"true\"\n");
		if (opnd_is_immed(opnd_src0))
		dr_fprintf(f, "  \"opnd_is_immed\"  : \"true\"\n");
		if (opnd_is_memory_reference(opnd_src0))
		dr_fprintf(f, "  \"opnd_is_memory_reference\"  : \"true\"\n");
		if (opnd_is_rel_addr(opnd_src0))
		dr_fprintf(f, "  \"opnd_is_rel_addr\"  : \"true\"\n");
		if (opnd_is_pc(opnd_src0))
		dr_fprintf(f, "  \"opnd_is_pc\"  : \"true\"\n");
		*/
		// --- End of maybe used in a future feature ---
	}
}

static void log_mem_at_reg_trace_instr(app_pc memaddr, char* regstr, file_t f) {

	size_t bytesread;
	size_t bytesbuf_len = 16;
	size_t resultstr_size;
	char* bytesstr;
	char* bytesbuf = (char*)dr_global_alloc(sizeof(char) * bytesbuf_len);

	if (dr_safe_read(memaddr, 16, bytesbuf, &bytesread)) {

		bytesstr = get_byte_string_trace_instr(bytesbuf, bytesread, &resultstr_size);
		if (bytesstr) {
			dr_fprintf(f, "  \"%s_ptr_data\"  : \"%s\",\n", regstr, bytesstr);
			dr_global_free(bytesstr, strlen(bytesstr) + 1);
			dr_global_free(bytesbuf, sizeof(char) * bytesbuf_len);
			return;
		}
		else {
			dr_global_free(bytesbuf, sizeof(char) * bytesbuf_len);
		}
	}
	dr_fprintf(f, "  \"%s_ptr_data\"  : \"NO_DATA\",\n", regstr);
}

static void handler_instr_is_return(file_t f, instr_t* instr, dr_mcontext_t* mc, size_t numbytes) {
	return;
}

static void handler_instr_is_call(file_t f, instr_t* instr, dr_mcontext_t* mc, size_t numbytes) {
	return;
}

static void handler_instr_is_pop(file_t f, instr_t* instr, dr_mcontext_t* mc, size_t numbytes) {
	return;
}

static void handler_instr_interesting_instr(file_t f, instr_t* instr, dr_mcontext_t* mc, size_t numbytes) {
	opnd_t op = instr_get_src(instr, 0);
	app_pc memaddr = my_opnd_compute_address(op, mc);
	size_t bytesread;

	uint instr_mem_size = instr_memory_reference_size(instr);

	char* bytesbuf = (char*)dr_global_alloc(sizeof(char) * numbytes);
	dr_safe_read(memaddr, numbytes, bytesbuf, &bytesread);

	log_bytestream_trace_instr(f, bytesbuf, bytesread, memaddr, instr_mem_size);

	dr_global_free(bytesbuf, sizeof(char) * numbytes);
	return;
}

static void handler_all_other_mem_instr(file_t f, instr_t* instr, dr_mcontext_t* mc, size_t numbytes) {

	opnd_t op = instr_get_src(instr, 0);
	app_pc memaddr = my_opnd_compute_address(op, mc);
	size_t bytesread;

	uint instr_mem_size = instr_memory_reference_size(instr);

	char* bytesbuf = (char*)dr_global_alloc(sizeof(char) * numbytes);
	dr_safe_read(memaddr, numbytes, bytesbuf, &bytesread);

	log_bytestream_trace_instr(f, bytesbuf, bytesread, memaddr, instr_mem_size);

	dr_global_free(bytesbuf, sizeof(char) * numbytes);

	return;
}


