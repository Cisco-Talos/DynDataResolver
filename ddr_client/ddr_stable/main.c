/*
-------------------------------------------------------------------------------
 
DDR IDA Pro Plug-in: Dynamic Data Resolver(DDR) backend DLL

Version 1.1 beta

Copyright(C) 2020 Cisco Talos
Author: Holger Unterbrink(hunterbr@cisco.com) Twitter: @hunterbr72

This software comes with no warranty you are using it at your own risk. 

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110 - 1301 USA.
 

Requirements
------------
DynamoRIO: http://dynamorio.org/

*/

#include "ddr.h"

// Globals
int cmd_opts;
unsigned int dbgLevel;
int tls_idx;
int tls_idx2;
int tls_idx3;
client_id_t my_id;
bool OEP_moved_plus = FALSE;
size_t oep_diff;
size_t ref_flags;
size_t from_addr = 0;
size_t to_addr = 0;
size_t inst_count = MAX_INSTR_COUNT;
size_t inst_num = 0;
bool light_trace_only = FALSE;
bool trace_set = FALSE;
bool first_instr_set = TRUE;

bool patch_eflag_set = FALSE;
P_EFLAG_PARA* pa_flag_para = NULL;
P_EFLAG_PARA* pa_flag_para_start = NULL;

bool patch_nop_set = FALSE;
P_NOP_PARA* pa_nop_para = NULL;
P_NOP_PARA* pa_nop_para_start = NULL;

bool patch_call_set = FALSE;
P_CALL_PARA* pa_call_para = NULL;
P_CALL_PARA* pa_call_para_start = NULL;

bool dump_buffer_set = FALSE;
S_DUMP_PARA* dump_para = NULL;
S_DUMP_PARA* dump_para_start = NULL;

bool trace_para_set = FALSE;
S_TRACE_PARA *trace_para = NULL;
S_TRACE_PARA *trace_para_start = NULL;

S_PROCS* pListThreads = NULL;
S_PROCS* pListThreads_start = NULL;
unsigned int thread_counter;
file_t global_fPidThreads;
char* global_pidThreadsFilename = "ddr_threads";
char* global_pidThreadsFullFilename;

bool dumpbuf_AddrFound = FALSE;
bool dumbuf_SizeFound = FALSE;

file_t global_f = NULL;
char *global_trace_LogFilename;
char *global_trace_ApiLogfilename;
char *global_client_path;
file_t global_trace_fp = NULL;
file_t global_trace_api_fp = NULL;
file_t global_exec_counter_fp = NULL;
unsigned int dr_exec_ctr = 1;

uint thread_couter   = 0;
thread_id_t thread_id  = 0;
process_id_t process_id      = 0;
thread_id_t first_thread_id = 0;

bool loop_set = false;
size_t loop_addr = (size_t) NULL;

bool startaddr_set = false;
size_t startaddr = (size_t) NULL;

bool breakaddr_set = false;
size_t breakaddr = (size_t)NULL;

TCHAR szName[]      = TEXT("DDRProcesscounter");  // shared memory object (used in ddr_helper_functions.c)
TCHAR szProcIDs[]   = TEXT("DDRProcessIDs");      // shared memory object (used in ddr_helper_functions.c)
TCHAR szProcNames[] = TEXT("DDRProcessNamess");   // shared memory object (used in ddr_helper_functions.c)
TCHAR szLogPath[]   = TEXT("DDRLogpath");         // shared memory object (used in ddr_helper_functions.c)
process_id_t* processids;
char* procnames;
char* global_logpath;

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[])
{
	debug_print("dr_client_main started.\n\n");

#ifdef _DEBUG
	dr_printf("-------------------------------------- Debugging Hint -------------------------------------------\n");
	dr_printf("Access violations from 'dynamorio!safe_read_asm_xxx' are expected and can be ignored in WinDbg.\n");
	dr_printf("They are caused by the way DynamoRio has implemented these functions.\n");
	dr_printf("They are handled by DynamoRio internally. Just proceed (F5) if something like below happens:\n\n");
	dr_printf("(1df0.1a28) : Access violation - code c0000005(first chance)\n");
	dr_printf("	 First chance exceptions are reported before any exception handling.\n");
	dr_printf("	 This exception may be expected and handled.\n");
	dr_printf("	 dynamorio!safe_read_asm_pre\n");
	dr_printf("------------------------------------------------------------------------------------------------\n\n");
#endif

	char* stmp;
	char* stmp2;
	size_t exec_bytes_read = 0;
	WINPATHCCHAPI HRESULT RemoveFilenameRes;
	
	dbgLevel = 0;
	thread_counter = 0; // number of threads running. Used to check when we can free global memory (process centric)

	dr_set_client_name("Dynamic Data Resolver", "hunterbr@cisco.com");
	
	drmgr_init();
	drwrap_init();
	my_id = id;

	// in case we are going to use a logfile in the future
	// dr_log(NULL, LOG_ALL, 1, "Client initializing...\n"); 
	debug_print("Start initalizing DynamoRio Client (ddr.dll)\n");

	// Set process counter and PID shared memory
	int Counter = IncProcCounter();
	processids = getSharedProcessIDs(processids);
	*(processids + Counter - 1) = dr_get_process_id();
	*(processids + Counter    ) = 0;
	debug_print("Saved PID %u in processids + %u\n", *(processids + Counter - 1), Counter - 1);

	// Set process names shared memory
	procnames = getSharedProcessNames(procnames);
	stmp2 = procnames + ((long long) Counter - 1) * MAX_PROCESSNAME;
	CopyMemory((PVOID)stmp2, dr_get_application_name(), MAX_PROCESSNAME * sizeof(char));
	*(stmp2 + MAX_PROCESSNAME - 1) = 0;
	debug_print("Saved Processname %s in processnames + %u\n", stmp2, ((long long) Counter - 1) * MAX_PROCESSNAME);

	// Set disassembler syntax to Intel style
	disassemble_set_syntax(DR_DISASM_INTEL);

	// Enable console output
	dr_enable_console_printing();

#ifdef X86_64
#ifdef _DEBUG
	dr_messagebox("New DDR instance started. Please attach windbg (\"C:\\tools\\dev\\WinDbg (x64-dynrio)\") to the sample process (PID: %u) now. Then click OK."
		, dr_get_process_id());
#endif
	dr_printf("\n[DDR] [INFO] DDR Client DLL x64 version %s initializing...\n", DDR_VERSION);
#else
#ifdef _DEBUG
	dr_messagebox("New DDR instance started. Pls attach windbg (\"C:\\tools\\dev\\WinDbg (x32-dynrio)\") to the sample process (PID: %u) now. Then click OK."
		, dr_get_process_id());
#endif
	dr_printf("\n[DDR] [INFO] DDR Client DLL x32 Version %s initializing...\n", DDR_VERSION);
#endif

	// Init global_logpath and let it point to shared memory object
	// We need shared memory because every process which is launched
	// by the sample will initalize a new ddr.dll instance,
	// which is a new process. In other words all objects we need in
	// all instances need to be shared memeory.
	global_logpath = getSharedLogpath(global_logpath);

	if(global_logpath == NULL) {
		dr_printf("[DDR] [ERROR] Failed to open global log path.");
		dr_exit_process(1);
	}	
	
	// get client library name (DDR32/64 DLL)
	global_client_path = _strdup(dr_get_client_path(id));
	stmp = strrchr(global_client_path, '\\');
	if (stmp != NULL) {
		*stmp = '\0';
	}
	else {
		global_client_path = NULL;
	}

	if (global_client_path == NULL) {
		dr_printf("[DDR] [ERROR] DDR DLL path not found\n");
		dr_exit_process(1);
	}
	else {
		dr_printf("[DDR] [INFO] DDR Client DLL running from: %s\n", global_client_path);
	}
	// Parse cmd line arguments. TBD: more input checks.
	cmd_opts = parse_cmd_opt();

	// ---- Register callback functions for events start ----
	// These functions are called when the corrosponding event occurs
	// e.g. a new thread is started -> event_thread_init_trace_instr

	// Start trace 
	if (cmd_opts & CmdOpt_NormalTrace) {
		dr_register_exit_event(event_exit);
		drmgr_register_module_load_event(event_module_load_trace_instr);			// executed on e.g. DLL load
		drmgr_register_bb_instrumentation_event(NULL, event_bb_instr_global, NULL); // executed on every basic block
		drmgr_register_thread_init_event(event_thread_init_trace_instr);			// executed on thread initalisation
		drmgr_register_thread_exit_event(event_thread_exit_trace_instr);			// executed on process exit 
	}
	// Dump memory buffer stored in operant n at programm counter
	else if ((cmd_opts & CmdOpt_DumpBuffer) || (cmd_opts & CmdOpt_Patch_EFLAG) || (cmd_opts & CmdOpt_Patch_NOP) || cmd_opts & CmdOpt_Patch_CALL) {
		dr_register_exit_event(event_exit);
		drmgr_register_bb_instrumentation_event(NULL, event_bb_instr_global, NULL);
		drmgr_register_thread_init_event(event_thread_init_global);
	}
	else if (cmd_opts & CmdOpt_Patch_Loop) {
		drmgr_register_bb_instrumentation_event(NULL, event_bb_instr_global, NULL);
	}
	// This should never happen
	else {
		dr_printf("[DDR] [ERROR] Unexpected command line parameter. This should not happen.\n");
		dr_exit_process(1);
	}
	// ---- Register callback functions for events end ----

#ifdef _DEBUG
	dr_printf("\n[DDR] [DEBUG] dr_client_main callbacks set.\n");
#endif

	// Init TLS helper vars. TBD: maybe we get rid of that in a future version.
	tls_idx = drmgr_register_tls_field();
	DR_ASSERT(tls_idx > -1);
	tls_idx2 = drmgr_register_tls_field();
	DR_ASSERT(tls_idx > -1);
	tls_idx3 = drmgr_register_tls_field();
	DR_ASSERT(tls_idx > -1);

	dr_printf("[DDR] [INFO] Initalization done.\n");
	debug_print("dr_client_main end.\n\n");
}

int parse_cmd_opt() {

	int ret=0;
	int argc, i = 0;
	char** argv; // , ** argv_tmp;
	char* filename = NULL;

	bool tstart_set = FALSE;
	bool tend_set = FALSE;
	bool tbreak_set = FALSE;
	bool num_instr_set = FALSE;
	bool fname_set = FALSE;
	bool dumpbuffer = FALSE;

	dr_get_option_array(my_id, &argc, &argv);

	while (++i < argc)  // Fix for a Ptr issue with while(++argv)[0] in DynRIO 
	{
		argv++;
		if (argv[0][0] == '-') {
			switch (argv[0][1]) {
			// Read patch/dump configuration from file 
			
			case 'c':
				if (!parse_cfgfile(argv[1])) {
					dr_printf("[DDR] [ERROR] Parsing config file failed\n");
					usage();
					dr_exit_process(1);
				}
				else { // Successfully parsed - move to next main argument
					argv += 1;
					i += 1;
				}
				break;
#ifdef _DEBUG
			case 'd':
				sscanf_s(argv[1], "%u", &dbgLevel);
				dr_printf("[DDR] [DEBUG] Debug verbose level set to %u", dbgLevel);
				break;
#endif
			// Help
			case 'h':
				usage();
				dr_exit_process(1);
			// Should not happen
			default: 
				dr_printf("[DDR] [ERROR] Unknown option -%c.\n", argv[0][1]);
				usage();
				dr_exit_process(1);
			}
		}
	}

	// --- TBD move checks to parsing routine ---

	if (loop_set) {
		if (!loop_addr) {
			dr_printf("[DDR] [ERROR] Failed parsing parameter for EFLAG patching.\n");
			usage();
			dr_exit_process(1);
		}
		else {
			dr_printf("[DDR] [INFO] Setting loop at PC address="PFX"\n", loop_addr);
			ret |= CmdOpt_Patch_Loop;
		}

	}

	// Patch executable via ELFAGS manipulation
	if (patch_eflag_set) {

		pa_flag_para = pa_flag_para_start; // set global patch EFLAG cmd entries pointer to the first entry of the linked list

		while (pa_flag_para) {
			if (!pa_flag_para->patch_eflag_PC || !pa_flag_para->patch_eflag_flag_str) {
				dr_printf("[DDR] [ERROR] Failed parsing parameter for EFLAG patching.\n");
				usage();
				dr_exit_process(1);
			}
			else {
				dr_printf("[DDR] [INFO] Toggle Flag=%s at PC address="PFX"\n", pa_flag_para->patch_eflag_flag_str, pa_flag_para->patch_eflag_PC);
			}
			pa_flag_para = pa_flag_para->nextpe;
		}
		pa_flag_para = pa_flag_para_start;
		ret |= CmdOpt_Patch_EFLAG;
	}
	// Patch executable with NOPs	
	if (patch_nop_set) {

		pa_nop_para_start = pa_nop_para;

		while (pa_nop_para) {
			if (!pa_nop_para->patch_nop_start_PC || !pa_nop_para->patch_nop_end_PC) {
				dr_printf("[DDR] [ERROR] Failed parsing parameter for NOP patching.\n");
				usage();
				dr_exit_process(1);
			}
			else {
				dr_printf("[DDR] [INFO] NOP'ing from "PFX" to "PFX"\n", pa_nop_para->patch_nop_start_PC, pa_nop_para->patch_nop_end_PC);
			}
			pa_nop_para = pa_nop_para->nextpa;
		}
		pa_nop_para = pa_nop_para_start;
		ret |= CmdOpt_Patch_NOP;
	}

	if (patch_call_set) {

		pa_call_para = pa_call_para_start;

		while (pa_call_para) {
			if (!pa_call_para->patch_call_func_PC) {
				dr_printf("[DDR] [ERROR] Failed parsing parameter for CALL function patching.\n");
				usage();
				dr_exit_process(1);
			}
			else {
				dr_printf("[DDR] [INFO] Wrapping function call at "PFX" and setting return value to "PFX"\n", pa_call_para->patch_call_func_PC, pa_call_para->patch_call_ret);
			}
			pa_call_para = pa_call_para->nextcp;
		}
		pa_call_para = pa_call_para_start;
		ret |= CmdOpt_Patch_CALL;
	}

	// Check if Dump and trace options are both set at the same time (not supported itm)
	if (dump_buffer_set && trace_set) {
		dr_printf("[DDR] [ERROR] You cannot use -d and -s at the same time.\n");
		usage();
		dr_exit_process(1);
	}

	// Dump buffer to file:
	if (dump_buffer_set) {

		i = 0;
		dump_para = dump_para_start;

		while (dump_para) {
			i++;
			if (!dump_para->bufferPC || !dump_para->sizePC || !dump_para->dumpPC || !dump_para->filename) {
				dr_printf("[DDR] [ERROR] DUMP%d: Missing PC parameter for dumping a buffer.\n");
				usage();
				dr_exit_process(1);
			}
			// check 'buffer' vars
			if (dump_para->bufferOptype != 'S' && dump_para->bufferOptype != 's' && dump_para->bufferOptype != 'D' && dump_para->bufferOptype != 'd') {
				dr_printf("[DDR] [ERROR] DUMP%d: Wrong <OP> buffer parameter in -d option. First character needs to be [SsDd] for [S]ource or [D]estination.\n",i);
				usage();
				dr_exit_process(1);
			}
			if (dump_para->bufferOptypePtrType != 'P' && dump_para->bufferOptypePtrType != 'p' && dump_para->bufferOptypePtrType != 'D' && dump_para->bufferOptypePtrType != 'd') {
				dr_printf("[DDR] [ERROR] DUMP%d: Wrong <OP> buffer parameter in -d option. Second character needs to be [PpDd] for [P]ointer or [D]oublePointer.\n",i);
				usage();
				dr_exit_process(1);
			}
			if (dump_para->bufferOpnum < 0 || dump_para->bufferOpnum > 5) {
				dr_printf("[DDR] [ERROR] DUMP%d: Wrong <OP> buffer parameter in -d option. Operant number must be between 0 and 5.\n",i);
				usage();
				dr_exit_process(1);
			}
			// check 'size' vars
			if (dump_para->sizeOptype != 'S' && dump_para->sizeOptype != 's' && dump_para->sizeOptype != 'D' && dump_para->sizeOptype != 'd') {
				dr_printf("[DDR] [ERROR] DUMP%d: Wrong <OP> size parameter in -d option. First character needs to be [SsDd] for [S]ource or [D]estination.\n",i);
				usage();
				dr_exit_process(1);
			}
			if (dump_para->sizeOptypePtrType != 'P' && dump_para->sizeOptypePtrType != 'p' && dump_para->sizeOptypePtrType != 'D' && dump_para->sizeOptypePtrType != 'd') {
				dr_printf("[DDR] [ERROR] DUMP%d: Wrong <OP> size parameter in -d option. Second character needs to be [PpDd] for [P]ointer or [D]oublePointer.\n",i);
				usage();
				dr_exit_process(1);
			}
			if (dump_para->sizeOpnum < 0 || dump_para->sizeOpnum > 5) {
				dr_printf("[DDR] [ERROR] DUMP%d: Wrong <OP> size parameter in -d option. Operant number must be between 0 and 5.\n",i);
				usage();
				dr_exit_process(1);
			}

			dr_printf("[DDR] [INFO] DUMP%d: Looking for buffer size at PC 0x%x with OPtyp:%c OPPtrTyp:%c OPnum:%d\n",i,dump_para->sizePC,dump_para->sizeOptype, dump_para->sizeOptypePtrType, dump_para->sizeOpnum);
			dr_printf("[DDR] [INFO] DUMP%d: Looking for buffer addr at PC 0x%x with OPtyp:%c OPPtrTyp:%c OPnum:%d\n",i,dump_para->bufferPC,dump_para->bufferOptype, dump_para->bufferOptypePtrType, dump_para->bufferOpnum);
			dr_printf("[DDR] [INFO] DUMP%d: Dumping buffer at "PFX"\n",i,dump_para->dumpPC);
			dr_printf("[DDR] [INFO] DUMP%d: Using dump file: %s.\n",i,dump_para->filename);

			ret |= CmdOpt_DumpBuffer;

			dump_para = dump_para->nextdp;
		}
		dump_para = dump_para_start;
	}

	// Normal trace:
	else if (trace_set) {
		if (!tstart_set) {
			dr_printf("[DDR] [ERROR] You need to set a start address (-s).\n");
			usage();
			dr_exit_process(1);
		}

		if (!tend_set) {
			dr_printf("[DDR] [ERROR] You need to set an end address (-e).\n");
			usage();
			dr_exit_process(1);
		}

		if (!fname_set || !global_trace_LogFilename) {
			dr_printf("[DDR] [ERROR] You need to set a log filename (-f).\n");
			usage();
			dr_exit_process(1);
		}

		dr_printf("[DDR] [INFO] Tracing file from "PFX" to "PFX"\n", from_addr, to_addr);

		ret |= CmdOpt_NormalTrace;
	}

	if (trace_para_set) {

		trace_para = trace_para_start;
		while (trace_para) {
			if (trace_para->light_trace_only) {
				dr_printf("[DDR] [INFO] Doing a light trace from "PFX" to "PFX" logging to %s\n", trace_para->start, trace_para->end, trace_para->filename);
			}
			else {
				dr_printf("[DDR] [INFO] Doing a full trace from "PFX" to "PFX" logging to %s\n", trace_para->start, trace_para->end, trace_para->filename);
			}
			trace_para = trace_para->nexttr;
		}
		trace_para = trace_para_start;

		ret |= CmdOpt_NormalTrace;
	}

	return ret;
}

void event_exit(void)
{ 
	debug_print("event_exit start. Process PID %u (%s)\n", dr_get_process_id(), dr_get_application_name());

	S_DUMP_PARA* dump_para_prev;
	S_TRACE_PARA* trace_para_prev;
	P_EFLAG_PARA* pa_flag_para_tmp;
	P_NOP_PARA* pa_nop_para_tmp;
	P_CALL_PARA* pa_call_para_tmp;

	unsigned int i, n;
	char logpath[MAX_PATH];
	bool timeout = TRUE;
	HANDLE hRunningProc;
	char* procname = NULL;
	process_id_t mypid = dr_get_process_id();
	file_t fPidsfile;
	char pidsfilename[MAX_PATH]; // e.g. "...\ddr_processtrace.txt" 
	module_data_t* app;

	if (dump_buffer_set) {
		debug_print("dump_buffer_set detected\n");
			dump_para = dump_para_start;
			while (dump_para) {
				debug_print("freeing dump_para list memory at "PFX"\n", dump_para);
				// First free the filename memory...
				dr_global_free(dump_para->filename, MAX_FILE_LINE_LEN);
				dump_para_prev = dump_para;
				// ... then the whole dump parameter linked list structure
				dump_para = dump_para->nextdp;
				dr_global_free(dump_para_prev, sizeof(S_DUMP_PARA));
			}
			debug_print("free'ed dump_para list memory.\n");
		}

	// free patch EFLAGS parameter linked list if it exists
	pa_flag_para = pa_flag_para_start;
	while (pa_flag_para) {
		debug_print("freeing pa_flag_para list memory at "PFX"\n", pa_flag_para);
		pa_flag_para_tmp = pa_flag_para->nextpe;
		dr_global_free(pa_flag_para, sizeof(P_EFLAG_PARA));
		pa_flag_para = pa_flag_para_tmp;
		debug_print("free'ed pa_flag_para list memory.\n");
	}

	//free patch NOP parameter linked list if exists
	pa_nop_para = pa_nop_para_start;
	while (pa_nop_para) {
		debug_print("freeing pa_nop_para list memory at "PFX"\n", pa_nop_para);
		pa_nop_para_tmp = pa_nop_para->nextpa;
		dr_global_free(pa_nop_para, sizeof(P_NOP_PARA));
		pa_nop_para = pa_nop_para_tmp;
		debug_print("free'ed pa_nop_para list memory.\n");
	}

	//pa_call_para->nextcp = dr_global_alloc(sizeof(P_CALL_PARA));
	pa_call_para = pa_call_para_start;
	while (pa_call_para) {
		debug_print("freeing pa_call_para list memory at "PFX"\n", pa_call_para);
		pa_call_para_tmp = pa_call_para->nextcp;
		dr_global_free(pa_call_para, sizeof(P_CALL_PARA));
		pa_call_para = pa_call_para_tmp;
		debug_print("free'ed pa_call_para list memory.\n");
	}

	if (trace_para_set) {
		trace_para = trace_para_start;
		while (trace_para) {
			dr_global_free(trace_para->filename, MAX_FILE_LINE_LEN);
			trace_para_prev = trace_para;
			trace_para = trace_para->nexttr;
			dr_global_free(trace_para_prev, sizeof(S_TRACE_PARA));
		}
	}

	// unregister TLS field vars
	drmgr_unregister_tls_field(tls_idx);
	drmgr_unregister_tls_field(tls_idx2);
	drmgr_unregister_tls_field(tls_idx3);

	drwrap_exit();
	
	// Process tracing monitoring and clean up
	if (trace_para_set) {
		processids = getSharedProcessIDs(processids);
		procnames = getSharedProcessNames(procnames);

		// Are we in the main process ?
		if (*processids == mypid) {
			dr_sleep(1000); // sleep one second to wait for other processes getting initalized, in case the sample started further processes.
		}

		// We are the last process running ?
		if (DecProcCounter() == 0) {
			debug_print("This is the last process running. No need to kill anything.\n");

			// Are we in the main process ? Write Process file to disk.
			if (*processids == mypid) {
				dr_printf("[DDR] [INFO] Main process PID %u (%s) process exit function reached. Writing process log file to disk.\n", mypid, procnames);
				app = dr_get_main_module();

				if (getLogFilePath(app->full_path, logpath) == NULL) {
					dr_printf("[DDR] [ERROR] [%s:%d] Failed to extract logpath from log filename\n.", __FILE__, __LINE__);
					dr_exit_process(1);
				}
				dr_free_module_data(app);
				debug_print("Using log path %s\n", logpath);

				dr_snprintf(pidsfilename, MAX_PATH, "%sddr_processtrace.txt", logpath);
				dr_printf("[DDR] [INFO] Writing process info to: %s\n", pidsfilename);

				fPidsfile = dr_open_file(pidsfilename, DR_FILE_WRITE_OVERWRITE);
				if (fPidsfile == INVALID_FILE) {
					dr_printf("[DDR] [ERROR] [%s:%d] Failed to open process log file: %s\n", pidsfilename, __FILE__, __LINE__);
					dr_exit_process(1);
				}

				for (n = 0; n < MAX_PROCESSES; n++) {
					if (*(processids + n) != 0) {
						procname = procnames + ((long long)n * MAX_PROCESSNAME);
						debug_print("writing processes to processfile: PID: %u (%s)\n", *(processids + n), procname);
						dr_fprintf(fPidsfile, "%s [%u]\r\n", procname, *(processids + n));
					}
				}
				dr_close_file(fPidsfile);
				drmgr_exit();
				return;
			}
			else {
				// Strange, it is the last process but it is not the main process ?
				dr_printf("[DDR] [INFO] Process PID %u (%s) process exit function reached. Writing process log file to disk.\n", mypid, procnames);
				dr_printf("[DDR] [INFO] This [PID %u (%s)] is not the main process, but the last process which was running.\n", mypid, procnames);
				drmgr_exit();
				return;
			}
		}
		else {
			// Are we in the main process but it is not the last process running ? Wait and then kill the other processes.
			if (*processids == mypid) {
				dr_printf("[DDR] [INFO] Main process PID %u (%s) process exit function reached. Waiting for other processes to exit.\n", mypid, procnames);
				app = dr_get_main_module();

				if (getLogFilePath(app->full_path, logpath) == NULL) {
					dr_printf("[DDR] [ERROR] [%s:%d] Failed to extract logpath from log filename\n.", __FILE__, __LINE__);
					dr_exit_process(1);
				}
				dr_free_module_data(app);
				debug_print("Using log path %s\n", logpath);

				dr_snprintf(pidsfilename, MAX_PATH, "%sddr_processtrace.txt", logpath);
				dr_printf("[DDR] [INFO] Writing process info to: %s\n", pidsfilename);

				fPidsfile = dr_open_file(pidsfilename, DR_FILE_WRITE_OVERWRITE);
				if (fPidsfile == INVALID_FILE) {
					dr_printf("[DDR] [ERROR] [%s:%d] Failed to open process log file: %s\n", pidsfilename, __FILE__, __LINE__);
					dr_exit_process(1);
				}

				for (n = 0; n < MAX_PROCESSES; n++) {
					if (*(processids + n) != 0) {
						procname = procnames + ((long long)n * MAX_PROCESSNAME);
						debug_print("writing processes to processfile: PID: %u (%s)\n", *(processids + n), procname);
						dr_fprintf(fPidsfile, "%s [%u]\r\n", procname, *(processids + n));
					}
				}
				dr_close_file(fPidsfile);

				// There are still other processes running
				for (i = 0; i <= MAX_SEC_TO_WAIT_FOR_PROCS; i++) {
					// Lets wait for the running processes
					if (GetProcCounter() == 0) {
						dr_printf("[DDR] [INFO] All processes launched by the sample were terminated before reaching timeout.\n");
						timeout = FALSE;
						break;
					}
					else {
						dr_printf("[DDR] [INFO] waiting for other processes to exit.\n");
					}
					dr_sleep(1000); // waiting for 1sec before next check.
				}

				if (timeout) {
					// Timeout while waiting for processes to exit. Some Processes are still running, we are killing them now.
					dr_printf("[DDR] [INFO] Time out reached. Some processes launched by the main process are still running. Trying to terminate them...\n");
					// killing up to MAX_PROCESSES processes which are still running
					for (n = 0; n < MAX_PROCESSES; n++) {
						if (*(processids + n) != 0) {
							if (*(processids + n) == mypid) {
								// don't kill yourself (main process)
								continue;
							}
							else {
								// kill all other processes the main process has started
								procname = procnames + ((long long)n * MAX_PROCESSNAME);
								if (procname == NULL) {
									procname = "Process name not found";
								}
								dr_printf("[DDR] [INFO] Trying to kill PID: %u (%s)\n", *(processids + n), procname);

								if (hRunningProc = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, TRUE, (DWORD) * (processids + n))) {
									if (TerminateProcess(hRunningProc, 0)) {
										dr_printf("[DDR] [INFO] PID: %u (%s) successfully terminated\n", *(processids + n), procname);
									}
									else {
										dr_printf("[DDR] [WARNING] Failed to terminate PID: %u (%s) maybe still running.\n", *(processids + n), procname);
									}
									CloseHandle(hRunningProc);
								}
								else {
									dr_printf("[DDR] [WARNING] Failed to open PID: %u (%s) for terminating it, maybe still running.\n", *(processids + n), procname);
								}
							}
						}
						else {
							break;
						}
					}
				}
			}
		}
	}
	
	drmgr_exit();

	debug_print("event_exit end.\n");
}

bool parse_cfgfile(char* filename) {

	dr_printf("[DDR] [INFO] Reading config from file: %s\n", filename);  // format: <flag> <addr> e.g. ZF 12345678

	FILE* dump_patch_cfg_file;
	errno_t err;
	char line[MAX_FILE_LINE_LEN];

	err = fopen_s(&dump_patch_cfg_file, filename, "r");
	if (err != 0) {
		dr_printf("[DDR] [ERROR] Can't read config file.\n\n");
		usage();
		dr_exit_process(1);
	}

	int i = 0;
	while (!feof(dump_patch_cfg_file)) {
		i++;
		if (fgets(line, MAX_FILE_LINE_LEN, dump_patch_cfg_file)) {
			if (strlen(line) > MAX_CFG_LINE) {
				dr_printf("[DDR] [ERROR] Config file line %d too long (%d chars). Lines longer than %d are not allowed\n", i, strlen(line), MAX_CFG_LINE);
				usage();
				dr_exit_process(1);
			}
			if (line[0] == '#' || line[0] == ' ' || strlen(line) < 5) {
				continue;
			}

			switch (tolower(line[0])) {
			// Toggle EFLAG option
			case 't':
				if (pa_flag_para) { // Is there already a list entry ?					
					if (pa_flag_para->nextpe = dr_global_alloc(sizeof(P_EFLAG_PARA))) {
						pa_flag_para = pa_flag_para->nextpe;
						// Init struct
						pa_flag_para->patch_eflag_flag_str = NULL;
						pa_flag_para->patch_eflag_flag = 0;
						pa_flag_para->patch_eflag_PC = 0;
						pa_flag_para->nextpe = NULL;
					}
					else {
						dr_printf("[DDR] [ERROR] Failed to allocate memory for pa_flag_para.");
						dr_exit_process(1);
					}
				}
				else { // first list entry
					if (pa_flag_para = dr_global_alloc(sizeof(P_EFLAG_PARA))) {
						pa_flag_para_start = pa_flag_para;
						// Init struct
						pa_flag_para->patch_eflag_flag_str = NULL;
						pa_flag_para->patch_eflag_flag = 0;
						pa_flag_para->patch_eflag_PC = 0;
						pa_flag_para->nextpe = NULL;
					}
					else {
						dr_printf("[DDR] [ERROR] Failed to allocate memory for first pa_flag_para.");
						dr_exit_process(1);
					}
				}
				if (!parse_patch_flag_line(line + 2)) {
					dr_printf("[DDR] [ERROR] [EFLAG] Parsing line %d in config file failed.\n",i);
					usage();
					dr_exit_process(1);
				}
				break;
			// NOP out option
			case 'n':
				if (pa_nop_para) { // Is there already a list entry ?
					pa_nop_para->nextpa = dr_global_alloc(sizeof(P_NOP_PARA));
					pa_nop_para = pa_nop_para->nextpa;
					// Init struct
					pa_nop_para->patch_nop_start_PC = 0;
					pa_nop_para->patch_nop_end_PC = 0;
					pa_nop_para->nextpa = NULL;
				}
				else { // first list entry
					pa_nop_para = dr_global_alloc(sizeof(P_NOP_PARA));
					pa_nop_para_start = pa_nop_para;
					// Init struct
					pa_nop_para->patch_nop_start_PC = 0;
					pa_nop_para->patch_nop_end_PC = 0;
					pa_nop_para->nextpa = NULL;
				}
				if (!parse_patch_nop_line(line + 2)) {
					dr_printf("[DDR] [ERROR] [NOP] Parsing line %d in config file failed.\n",i);
					usage();
					dr_exit_process(1);
				}
				break;
			// Bypass all function calls to function x and set ret value
			case 'c':
				if (pa_call_para) { // Is there already a list entry ?
					pa_call_para->nextcp = dr_global_alloc(sizeof(P_CALL_PARA));
					pa_call_para = pa_call_para->nextcp;
					// Init struct
					pa_call_para->patch_call_func_PC = 0;
					pa_call_para->patch_call_ret = 0;
					pa_call_para->nextcp = NULL;
				}
				else { // first list entry
					pa_call_para = dr_global_alloc(sizeof(P_CALL_PARA));
					pa_call_para_start = pa_call_para;
					// Init struct
					pa_call_para->patch_call_func_PC = 0;
					pa_call_para->patch_call_ret = 0;
					pa_call_para->nextcp = NULL;
				}
				if (!parse_patch_call_line(line + 2)) {
					dr_printf("[DDR] [ERROR] [CALL] Parsing line %d in config file failed.\n",i);
					usage();
					dr_exit_process(1);
				}

				break;
			// Dump buffer to disk
			case 'd':
				if (dump_para) { // Is there already a list entry ?
					dump_para->nextdp = dr_global_alloc(sizeof(S_DUMP_PARA));
					dump_para = dump_para->nextdp;
					// Init struct
					dump_para->bufferPC = 0;
					dump_para->bufferOp = NULL;
					dump_para->bufferOpnum = 0;
					dump_para->bufferOptype = 0;
					dump_para->bufferOptypePtrType = 0;
					dump_para->sizePC = 0;
					dump_para->sizeOp = NULL;
					dump_para->sizeOpnum = 0;
					dump_para->sizeOptype = 0;
					dump_para->sizeOptypePtrType = 0;
					dump_para->dumpPC = 0;
					dump_para->filename = NULL;
					dump_para->nextdp = NULL;
				}
				else { // first list entry
					dump_para = dr_global_alloc(sizeof(S_DUMP_PARA));
					dump_para_start = dump_para;
					// Init struct
					dump_para->bufferPC = 0;
					dump_para->bufferOp = NULL;
					dump_para->bufferOpnum = 0;
					dump_para->bufferOptype = 0;
					dump_para->bufferOptypePtrType = 0;
					dump_para->sizePC = 0;
					dump_para->sizeOp = NULL;
					dump_para->sizeOpnum = 0;
					dump_para->sizeOptype = 0;
					dump_para->sizeOptypePtrType = 0;
					dump_para->dumpPC = 0;
					dump_para->filename = NULL;
					dump_para->nextdp = NULL;
				}

				if (!parse_dump_buffer_line(line + 2, i)) {
					dr_printf("[DDR] [ERROR] [DUMP] Parsing line %d in config file failed.\n",i);
					usage();
					dr_exit_process(1);
				}
				break;
			// trace instructions
			case 'l':
				if (trace_para) { // Is there already a list entry ?
					trace_para->nexttr = dr_global_alloc(sizeof(S_TRACE_PARA));
					trace_para = trace_para->nexttr;
					// Init struct
					trace_para->start = 0;
					trace_para->end = 0;
					trace_para->max_instr = 0;
					trace_para->light_trace_only = FALSE;
					trace_para->filename = NULL;
					trace_para->nexttr = NULL;
				}
				else { // first list entry
					trace_para = dr_global_alloc(sizeof(S_TRACE_PARA));
					trace_para_start = trace_para;
					// Init struct
					trace_para->start				= 0;
					trace_para->end					= 0;
					trace_para->max_instr			= 0;
					trace_para->light_trace_only	= FALSE;
					trace_para->filename			= NULL;
					trace_para->nexttr				= NULL;		
				}
				if (!parse_trace_line(line + 2, i)) {
					dr_printf("[DDR] [ERROR] [TRACE] Parsing line %d in config file failed.\n",i);
					usage();
					dr_exit_process(1);
				}
				break;

			// Loop at address
			case 'b':
				if (!parse_loop_line(line + 2, i)) {
					dr_printf("[DDR] [ERROR] [TRACE] Parsing line %d in config file failed.\n", i);
					usage();
					dr_exit_process(1);
				}
				break;

			// break address 
			case 'a':
				if (!parse_breakaddr_line(line + 2, i)) {
					dr_printf("[DDR] [ERROR] [BREAKADDR] Parsing line %d in config file failed.\n", i);
					usage();
					dr_exit_process(1);
				}
				break;
			
			// start address 
			case 's':
				if (!parse_startaddr_line(line + 2, i)) {
					dr_printf("[DDR] [ERROR] [BREAKADDR] Parsing line %d in config file failed.\n", i);
					usage();
					dr_exit_process(1);
				}
				break;

			// Should not happen...
			default:
				dr_printf("[DDR] [ERROR] Unknown option \"%c\" in patch cfgfile\n\n", line[0]);
				usage();
				dr_exit_process(1);
			}
		}
	}

	pa_flag_para = pa_flag_para_start;
	pa_nop_para = pa_nop_para_start;
	pa_call_para = pa_call_para_start;
	dump_para = dump_para_start;
	trace_para = trace_para_start;

	err = fclose(dump_patch_cfg_file);
	if (err == 0)
	{
		dr_printf("[DDR] [INFO] Configuration file closed\n");
	}
	else
	{
		dr_printf("[DDR] [ERROR] Failed closing configuration file\n");
	}
	return TRUE;
}


bool parse_loop_line(char* line, unsigned int linenr) {

	line[PATCH_ADDR_SIZE] = '\0'; // remove all comments if there are any
	loop_addr = (size_t)strtoull(line, NULL, 16);
	loop_set = true;
	return true;
}

bool parse_startaddr_line(char* line, unsigned int linenr) {

	line[PATCH_ADDR_SIZE] = '\0'; // remove all comments if there are any
	startaddr = (size_t)strtoull(line, NULL, 16);
    startaddr_set = true;
	return true;
}

bool parse_breakaddr_line(char* line, unsigned int linenr) {

	line[PATCH_ADDR_SIZE] = '\0'; // remove all comments if there are any
	breakaddr = (size_t)strtoull(line, NULL, 16);
	breakaddr_set = true;
	return true;
}

bool parse_patch_flag_line(char* line) {

	bool parafound = FALSE;
	unsigned int i = 0;
	char flagname[3];
	char addr[PATCH_ADDR_SIZE + 1];

	line[4 + PATCH_ADDR_SIZE] = '\0'; // remove all comments if there are any

	dr_sscanf(line, "%s %s\n", flagname, addr);
	flagname[2]               = '\0';
	addr[PATCH_ADDR_SIZE]     = '\0';

	pa_flag_para->patch_eflag_flag_str = strtoupper(flagname);

	switch (djb2_hash(pa_flag_para->patch_eflag_flag_str)) {
	case (CF):
		pa_flag_para->patch_eflag_flag = EFLAGS_CF;
		pa_flag_para->patch_eflag_PC = (size_t)strtoull(addr, NULL, 16);
		pa_flag_para->patch_eflag_flag_str = "CF";
		parafound = TRUE;
		break;
	case (PF):
		pa_flag_para->patch_eflag_flag = EFLAGS_PF;
		pa_flag_para->patch_eflag_PC = (size_t)strtoull(addr, NULL, 16);
		pa_flag_para->patch_eflag_flag_str = "PF";
		parafound = TRUE;
		break;
	case (AF):
		pa_flag_para->patch_eflag_flag = EFLAGS_AF;
		pa_flag_para->patch_eflag_PC = (size_t)strtoull(addr, NULL, 16);
		pa_flag_para->patch_eflag_flag_str = "AF";
		parafound = TRUE;
		break;
	case (ZF):
		pa_flag_para->patch_eflag_flag = EFLAGS_ZF;
		pa_flag_para->patch_eflag_PC = (size_t)strtoull(addr, NULL, 16);
		pa_flag_para->patch_eflag_flag_str = "ZF";
		parafound = TRUE;
		break;
	case (SF):
		pa_flag_para->patch_eflag_flag = EFLAGS_SF;
		pa_flag_para->patch_eflag_PC = (size_t)strtoull(addr, NULL, 16);
		pa_flag_para->patch_eflag_flag_str = "SF";
		parafound = TRUE;
		break;
	case (DF):
		pa_flag_para->patch_eflag_flag = EFLAGS_DF;
		pa_flag_para->patch_eflag_PC = (size_t)strtoull(addr, NULL, 16);
		pa_flag_para->patch_eflag_flag_str = "DF";
		parafound = TRUE;
		break;
	case (OF):
		pa_flag_para->patch_eflag_flag = EFLAGS_OF;
		pa_flag_para->patch_eflag_PC = (size_t)strtoull(addr, NULL, 16);
		pa_flag_para->patch_eflag_flag_str = "OF";
		parafound = TRUE;
		break;
	}

	if (parafound) {
		patch_eflag_set = TRUE;
		return TRUE;
	}
	else {
		return FALSE;
	}
}

bool parse_patch_nop_line(char* line) {

	char nop_start_str[PATCH_ADDR_SIZE + 1];
	char nop_end_str[PATCH_ADDR_SIZE + 1];

	dr_sscanf(line, "%s %s\n", nop_start_str, nop_end_str);
	nop_start_str[PATCH_ADDR_SIZE] = '\0';
	nop_end_str[PATCH_ADDR_SIZE]   = '\0';

	pa_nop_para->patch_nop_start_PC = (size_t)strtoull(nop_start_str, NULL, 16);
	pa_nop_para->patch_nop_end_PC = (size_t)strtoull(nop_end_str, NULL, 16);

	if (!pa_nop_para->patch_nop_start_PC || !pa_nop_para->patch_nop_end_PC) {
		return FALSE;
	}
	else {
		patch_nop_set = TRUE;
		return TRUE;
	}
}

bool parse_patch_call_line(char* line) {

	char call_func_str[PATCH_ADDR_SIZE + 1];
	char call_ret_str[PATCH_ADDR_SIZE + 1];

	dr_sscanf(line, "%s %s\n", call_func_str, call_ret_str);
	call_func_str[PATCH_ADDR_SIZE] = '\0';
	call_ret_str[PATCH_ADDR_SIZE]  = '\0';

	pa_call_para->patch_call_func_PC = (size_t)strtoull(call_func_str, NULL, 16);
	pa_call_para->patch_call_ret = (size_t)strtoull(call_ret_str, NULL, 16);

	if (!pa_call_para->patch_call_func_PC) {
		return FALSE;
	}
	else {
		patch_call_set = TRUE;
		return TRUE;
	}
}

bool parse_dump_buffer_line(char* line, unsigned int linenr) {

	char* sizePC = dr_global_alloc(MAX_FILE_LINE_LEN);
	char* sizeOp = dr_global_alloc(MAX_FILE_LINE_LEN);
	char* bufferPC = dr_global_alloc(MAX_FILE_LINE_LEN);
	char* bufferOp = dr_global_alloc(MAX_FILE_LINE_LEN);
	char* dumpPC = dr_global_alloc(MAX_FILE_LINE_LEN);
	char* filename = dr_global_alloc(MAX_FILE_LINE_LEN);

	//e.g. line = "0040117E SP0 0040118B SP0 004011F9 dump1.bin"
	//char* format = "%s %s %s %s %s %s";
	//dr_sscanf(line, format, sizePC, sizeOp, bufferPC, bufferOp, dumpPC, filename);

	//e.g. line = "0040117E SP0 0040118B SP0 004011F9 "C:\Users\test\Documents\test\test\dump1.bin"
	//e.g. line = "0040117E SP0 0040118B SP0 004011F9 dump1.bin"
	char format[100];
	dr_snprintf(format, 100, "%s%d%s", "%s %s %s %s %s \"%", MAX_DUMP_FILENAME, "[^\"]");  // -> e.g. '%s %s %s %s %s "%256[^"]"'
	dr_sscanf(line, format, sizePC, sizeOp, bufferPC, bufferOp, dumpPC, filename);

	if (!strcmp(filename, "")) {
		dr_snprintf(format, 100, "%s", "%s %s %s %s %s %s");
		dr_sscanf(line, format, sizePC, sizeOp, bufferPC, bufferOp, dumpPC, filename);
	}

	check_strlen(sizePC, sizeof(size_t) * 2, "Buffer size PC field in config file is too long", linenr);
	check_strlen(sizeOp, 3, "Buffer size OP field in config file is too long", linenr);
	check_strlen(bufferPC, sizeof(size_t) * 2, "Buffer address PC field in config file is too long", linenr);
	check_strlen(bufferOp, 3, "Buffer address OP field in config file is too long", linenr);
	check_strlen(dumpPC, sizeof(size_t) * 2, "Dump buffer PC field in config file is too long", linenr);
	check_strlen(filename, MAX_DUMP_FILENAME, "Dump filename field in config file is too long", linenr);

	dump_para->sizePC = (size_t)strtoull(sizePC, NULL, 16);
	dump_para->sizeOp = sizeOp;

	dump_para->bufferPC = (size_t)strtoull(bufferPC, NULL, 16);
	dump_para->bufferOp = bufferOp;

	dump_para->dumpPC = (size_t)strtoull(dumpPC, NULL, 16);

	dump_para->bufferOptype = dump_para->bufferOp[0];
	dump_para->bufferOptypePtrType = dump_para->bufferOp[1];
	dump_para->bufferOpnum = (int)strtoull(dump_para->bufferOp + 2, NULL, 10);

	dump_para->sizeOptype = dump_para->sizeOp[0];
	dump_para->sizeOptypePtrType = dump_para->sizeOp[1];
	dump_para->sizeOpnum = (int)strtoull(dump_para->sizeOp + 2, NULL, 10);

	dump_para->filename = filename;

	if (dump_para->sizePC && dump_para->sizeOp && dump_para->bufferPC && dump_para->bufferOp && dump_para->dumpPC && dump_para->filename) {
		dump_buffer_set = TRUE;
		dr_global_free(sizePC,   MAX_FILE_LINE_LEN);
		dr_global_free(sizeOp,   MAX_FILE_LINE_LEN);
		dr_global_free(bufferPC, MAX_FILE_LINE_LEN);
		dr_global_free(bufferOp, MAX_FILE_LINE_LEN);
		dr_global_free(dumpPC,   MAX_FILE_LINE_LEN);
		return TRUE;
	}

	dr_global_free(sizePC, MAX_FILE_LINE_LEN);
	dr_global_free(sizeOp, MAX_FILE_LINE_LEN);
	dr_global_free(bufferPC, MAX_FILE_LINE_LEN);
	dr_global_free(bufferOp, MAX_FILE_LINE_LEN);
	dr_global_free(dumpPC, MAX_FILE_LINE_LEN);
	return FALSE;
}

void trace_para_sanity_check(S_TRACE_PARA* trace_para, unsigned int linenr) {

	// is start-end a valid range ?
	if (trace_para->start > trace_para->end) {
		dr_printf("[DDR] [ERROR] Configuration file error (Line %d): Trace start parameter is larger than the end parameter.\n", linenr);
		dr_abort();
	}
}

bool parse_trace_line(char* line, unsigned int linenr) {

	char* stmp;
	char  stmp2[MAX_PATH];
	int parse_failed_pos = 0;
	// make sure you free these global allocs after use
	char* start				    = dr_global_alloc(MAX_FILE_LINE_LEN);
	char* end				    = dr_global_alloc(MAX_FILE_LINE_LEN);
	char* max_instr			    = dr_global_alloc(MAX_FILE_LINE_LEN);
	char* loc_light_trace_only	= dr_global_alloc(MAX_FILE_LINE_LEN);
	char* filename			    = dr_global_alloc(MAX_FILE_LINE_LEN);

	//            # start  end    max.instr  lighttrace filename (the last in the list will be used)
	//e.g. line = L 401000 482000 20000      TRUE       "C:\Users\test\Documents\test\test\lighttraceiiii.json"
	//or   line = L 401000 482000 20000      TRUE       lighttraceiiii.json

	char format[100];
	dr_snprintf(format, 100, "%s%d%s", "%s %s %s %s \"%", MAX_TRACE_FILENAME, "[^\"]");  // -> e.g. '%s %s %s %s %s "%256[^"]"'
	dr_sscanf(line, format, start, end, max_instr, loc_light_trace_only, filename);

	if (!strcmp(filename,"")) {
		dr_snprintf(format, 100, "%s", "%s %s %s %s %s");
		dr_sscanf(line, format, start, end, max_instr, loc_light_trace_only, filename);
	}

	// filename (last field) will be uninitalized aka not ascii if config file is missing a parameter
	if (!isascii(*filename)) {
		dr_printf("[DDR] [ERROR] Configuration file format error in line %d. \n", linenr);
		dr_printf("[DDR] [ERROR] At least one parameter field is missing or a non ASCII character found.\n");
		dr_abort();
	}

	check_strlen(start					, sizeof(size_t) * 2, "Start PC field in config file is too long", linenr);
	check_strlen(end					, sizeof(size_t) * 2, "End PC field in config file is too long", linenr);
	check_strlen(max_instr				, sizeof(size_t) * 2, "Max. instructions field in config file is too long", linenr);
	check_strlen(loc_light_trace_only	, strlen("FALSE")   , "Light trace only field in config file is too long", linenr);
	check_strlen(filename				, MAX_TRACE_FILENAME, "Dump filename field in config file is too long", linenr);

	// convert string values and save them into the global trace_para struct
	trace_para->start			= (size_t)strtoull(start, NULL, 16);
	trace_para->end				= (size_t)strtoull(end  , NULL, 16);
	trace_para->max_instr		= (size_t)strtoull(max_instr, NULL, 16);
	trace_para->filename		= escape_filename(filename);

	trace_para_sanity_check(trace_para, linenr);

	// Light or full trace ?
	loc_light_trace_only = strtoupper(loc_light_trace_only);
	if (!strcmp(loc_light_trace_only, "TRUE")) {
		trace_para->light_trace_only = TRUE;
		//dr_printf("[DDR] [INFO] Light trace set\n");
	}
	else {
		trace_para->light_trace_only = FALSE;
		//dr_printf("[DDR] [INFO] Full trace set\n");
	}
	
	// setup trace loggin files
	if (global_trace_LogFilename == NULL) { // only create log files if this is the first trace line in the cfg file.
		global_trace_LogFilename = dr_global_alloc(MAX_PATH);
		strcpy_s(global_trace_LogFilename, MAX_PATH, trace_para->filename);

		// Verify length of handed over log filename
		if (strlen(global_trace_LogFilename) >= MAX_PATH - strlen("_apicalls.json") - 20) {
			dr_printf("[DDR] [ERROR] Trace LogFilename is too long.\n");
			dr_abort();
		}

		// --- Open instruction log file. ----
		dr_printf("[DDR] [INFO] Trying to use trace logfile: %s\n", global_trace_LogFilename);

		// If file exists create new one with app name and pid
		if (CheckFileExists(global_trace_LogFilename)) {
			dr_printf("[DDR] [INFO] Logfile exists\n");
			stmp = strrchr(global_trace_LogFilename, '.');
			if (stmp != NULL)
				*stmp = '\0';
			else {
				dr_printf("[DDR] [INFO] Failed to terminate string\n");
			}
			// add number to logfile name
			snprintf(stmp2, MAX_PATH, "_%s_%u.json", dr_get_application_name(), (uint)dr_get_process_id());
			strcat_s(global_trace_LogFilename, MAX_PATH, stmp2);
			dr_printf("[DDR] [INFO] Using new trace logfile: %s\n", global_trace_LogFilename);
		}
		// Open file
		global_trace_fp = dr_open_file(global_trace_LogFilename, DR_FILE_WRITE_OVERWRITE);
		if (global_trace_fp == INVALID_FILE) {
			dr_printf("[DDR] [ERROR] Can't create instruction log file. Does the directory you specified exist?\n");
			dr_printf("[DDR] [ERROR] Tried log filename: '%s'\n", global_trace_LogFilename);
			dr_exit_process(1);
		}

		// ---- Open api call log file. ----
		global_trace_ApiLogfilename = dr_global_alloc(MAX_PATH);
		strcpy_s(global_trace_ApiLogfilename, MAX_PATH, global_trace_LogFilename);
		stmp = strrchr(global_trace_ApiLogfilename, '.');
		if (stmp != NULL)
			*stmp = '\0';
		strcat_s(global_trace_ApiLogfilename, MAX_PATH, "_apicalls.json");
		// Open file
		global_trace_api_fp = dr_open_file(global_trace_ApiLogfilename, DR_FILE_WRITE_OVERWRITE);
		if (global_trace_api_fp == INVALID_FILE) {
			dr_printf("[DDR] [ERROR] Can't create API log file. Does the directory you specified exist?\n");
			dr_printf("[DDR] [ERROR] Tried API log filename: '%s'\n", global_trace_ApiLogfilename);
			dr_exit_process(1);
		}

		dr_fprintf(global_trace_api_fp, "{\n\"apicalls\" :\n [\n"); // init file header
		dr_printf("[DDR] [INFO] Done creating logfiles.\n");
	}
	

	if (trace_para->start && trace_para->end && trace_para->filename) {
		trace_para_set = TRUE;

		dr_global_free(start, MAX_FILE_LINE_LEN);
		dr_global_free(end, MAX_FILE_LINE_LEN);
		dr_global_free(max_instr, MAX_FILE_LINE_LEN);
		dr_global_free(loc_light_trace_only, MAX_FILE_LINE_LEN);

		return TRUE;
	}
	
	dr_global_free(start, MAX_FILE_LINE_LEN);
	dr_global_free(end, MAX_FILE_LINE_LEN);
	dr_global_free(max_instr, MAX_FILE_LINE_LEN);
	dr_global_free(loc_light_trace_only, MAX_FILE_LINE_LEN);

	return FALSE;
}

void __cdecl clean_exit_workaround(app_pc instr_addr, int exit_code) {
	// Workaround for "Rank order violation all_threads_synch_lock(mutex): acquired after bb_building_lock issue" 
	// Otherwise dr_exit_process crashes if used directly in "event_bb_instr_global" function.
	dr_printf("[DDR] [INFO] Exiting process...");
	dr_exit_process(exit_code);
}

dr_emit_flags_t event_bb_instr_global(void* drcontext, void* tag, instrlist_t* bb, instr_t* instr, bool for_trace, bool translating, void* user_data) {

	app_pc instr_addr;
	size_t instr_addr_fixed;
	static bool startoffset_found;

	instr_addr = instr_get_app_pc(instr);

	// fix addresses for position independent code
	if (!OEP_moved_plus)
		instr_addr_fixed = (size_t)instr_addr + oep_diff;
	else
		instr_addr_fixed = (size_t)instr_addr - oep_diff;

	// only trace sample applications instructions
	if (instr_is_app(instr)) {
		
		// If start address was set, wait until 'start offset' is found with instrumentation. 
		// Once we passed the start offset, instrumentation starts
		if (startaddr_set) {
			if (instr_addr_fixed != startaddr && startoffset_found == FALSE) {
				return DR_EMIT_DEFAULT;
			}
			else {
				startoffset_found = TRUE;
			}
		}

		if (breakaddr_set) {
			if (instr_addr_fixed == breakaddr) {
				dr_printf("[DDR] [INFO] Break address.");
				dr_insert_clean_call(drcontext, bb, instr, clean_exit_workaround, FALSE, 2, OPND_CREATE_INTPTR(instr_addr), OPND_CREATE_INTPTR(0));
			}
		}

		// trace instrumentation needs to go first, it might be overwritten by dump, patch_flags etc., last instrumentation for an PC addr wins.
		if (trace_para_set) {
			while (trace_para) {
				if ((instr_addr_fixed >= trace_para->start) && (instr_addr_fixed <= trace_para->end)) {
					// insert analysing function into basic block. Called for each basic block instruction.
					dr_insert_clean_call(drcontext, bb, instr, process_instr_trace_instr_new, FALSE, 2, OPND_CREATE_INTPTR(instr_addr), OPND_CREATE_INTPTR(trace_para));
				}
				trace_para = trace_para->nexttr;
			}
			trace_para = trace_para_start;
		}

		if (dump_buffer_set) {
			dump_para_start = dump_para;

			while (dump_para) {

				if (instr_addr_fixed == dump_para->sizePC) {
					// we don't need the the fp/mmx state itm, so save_fpstate=FALSE
					dr_insert_clean_call(drcontext, bb, instr, process_instr_size_dump_buffer, FALSE, 2, OPND_CREATE_INTPTR(instr_addr), OPND_CREATE_INTPTR(dump_para));
				}
				if (instr_addr_fixed == dump_para->bufferPC) {
					// we don't need the the fp/mmx state itm, so save_fpstate=FALSE
					dr_insert_clean_call(drcontext, bb, instr, process_instr_addr_dump_buffer, FALSE, 2, OPND_CREATE_INTPTR(instr_addr), OPND_CREATE_INTPTR(dump_para));
				}
				if (instr_addr_fixed == dump_para->dumpPC) {
					if (dumpbuf_AddrFound && dumbuf_SizeFound) {
						dr_insert_clean_call(drcontext, bb, instr, process_instr_dump_buffer, FALSE, 2, OPND_CREATE_INTPTR(instr_addr), OPND_CREATE_INTPTR(dump_para));
					}
					else {
						dr_printf("[DDR] [ERROR] Couldn't dump buffer at PC "PFX". Buffer address or size not found.\n", dump_para->dumpPC);
						dr_exit_process(1);
					}

				}
				dump_para = dump_para->nextdp;
			}
			dump_para = dump_para_start;
		}

		if (patch_eflag_set) { // Should we toggle the EFLAGs flag ?
			while (pa_flag_para) { // interate through Patch EFLAGS commandline entries
				if (instr_addr_fixed == pa_flag_para->patch_eflag_PC) {
					dr_insert_clean_call(drcontext, bb, instr, patch_eflag, FALSE, 2, OPND_CREATE_INTPTR(instr_addr), OPND_CREATE_INTPTR(pa_flag_para));
				}
				pa_flag_para = pa_flag_para->nextpe;
			}
			pa_flag_para = pa_flag_para_start;
		}

		if (patch_nop_set) { // Should we nop out instructions ?
			pa_nop_para_start = pa_nop_para;
			while (pa_nop_para) { // interate through patch nop config entries
				if (instr_addr_fixed >= (pa_nop_para->patch_nop_start_PC) && instr_addr_fixed <= (pa_nop_para->patch_nop_end_PC)) {
					dr_printf("[DDR] [INFO] NOP'ing instruction at "PFX":\n", instr_addr_fixed);

					// TBD verify if this works for x32/64 instr and all call conventions
					print_disasm(drcontext, instr_addr, instr_addr_fixed);
					instr_t* newnop = INSTR_CREATE_nop(drcontext);
					if (instr_get_prefix_flag(instr, PREFIX_LOCK)) {
						instr_set_prefix_flag(newnop, PREFIX_LOCK);
					}
					instr_set_translation(newnop, instr_get_app_pc(instr));
					instrlist_replace(bb, instr, newnop);
					instr_destroy(drcontext, instr);
				}
				pa_nop_para = pa_nop_para->nextpa;
			}
			pa_nop_para = pa_nop_para_start;
		}

		if (loop_set) {
			if (instr_addr_fixed == loop_addr) {
				dr_printf("[DDR] [INFO] Setting loop at "PFX":\n", loop_addr);
				dr_printf("[DDR] [INFO] Setting loop at "PFX":\n", instr_addr);
				dr_messagebox("Execution stopped. Please click ok to proceed.");
				dr_printf("[DDR] [INFO] Done msgbox.\n");
								
				print_disasm(drcontext, instr_addr, instr_addr_fixed);
				instr_t* newnop = instr_create_0dst_0src(drcontext, 0xcc);
				
				if (instr_get_prefix_flag(instr, PREFIX_LOCK)) {
					instr_set_prefix_flag(newnop, PREFIX_LOCK);
				}
				instr_set_translation(newnop, instr_get_app_pc(instr));
				instrlist_replace(bb, instr, newnop);
				instr_destroy(drcontext, instr);
			}
		}
	}
	return DR_EMIT_DEFAULT;
}

