#pragma once

extern int cmd_opts;
extern unsigned int dbgLevel;
extern int tls_idx;
extern int tls_idx2;
extern int tls_idx3;
extern client_id_t my_id;
extern size_t oep_diff;
extern size_t ref_flags;
extern size_t from_addr;
extern size_t to_addr;
extern size_t break_addr;
extern size_t inst_count;
extern size_t inst_num;
extern bool light_trace_only;
extern bool trace_set;
extern bool first_instr_set;
extern bool OEP_moved_plus;

extern bool patch_eflag_set;
extern P_EFLAG_PARA* pa_flag_para;
extern P_EFLAG_PARA* pa_flag_para_start;

extern bool patch_nop_set;
extern P_NOP_PARA* pa_nop_para;
extern P_NOP_PARA* pa_nop_para_start;

extern bool patch_call_set;
extern P_CALL_PARA* pa_call_para;
extern P_CALL_PARA* pa_call_para_start;

extern bool dump_buffer_set;
extern S_DUMP_PARA* dump_para;
extern S_DUMP_PARA* dump_para_start;

extern bool trace_para_set;
extern S_TRACE_PARA* trace_para;
extern S_TRACE_PARA* trace_para_start;

extern S_PROCS* pListThreads;
extern S_PROCS* pListThreads_start;
extern unsigned int thread_counter;

extern file_t global_fPidThreads;
extern char*  global_pidThreadsFilename;
extern char*  global_pidThreadsFullFilename;
extern char*  global_logpath;

extern bool dumpbuf_AddrFound;
extern bool dumbuf_SizeFound;

extern char *global_trace_LogFilename;
extern char *global_trace_ApiLogfilename;
extern char* global_client_path;
extern file_t global_trace_fp;
extern file_t global_trace_api_fp;
extern file_t global_exec_counter_fp;
extern uint thread_couter;
extern thread_id_t thread_id;
extern process_id_t process_id;
extern thread_id_t first_thread_id;
extern unsigned int dr_exec_ctr;

extern bool loop_set;
extern size_t loop_addr;

extern TCHAR szName[];
extern TCHAR szProcIDs[];
extern TCHAR szProcNames[];
extern TCHAR szLogPath[];
extern process_id_t *processids;

