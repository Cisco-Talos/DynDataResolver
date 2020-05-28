#pragma once
#include "dr_api.h"
#include "drmgr.h"
//#include "utils.h"
#include "drreg.h"
#include "drx.h"
#include "drwrap.h"
#include "dr_tools.h"

#include <windows.h>
#include <strsafe.h>
#include <malloc.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// --- Defines ---
#define CmdOpt_NormalTrace 1
#define CmdOpt_DumpBuffer  2
#define CmdOpt_Patch_EFLAG 4
#define CmdOpt_Patch_NOP   8
#define CmdOpt_Patch_CALL  16
#define CmdOpt_Patch_Loop  32

#ifdef X86_64
  #define PATCH_ADDR_SIZE 16
#else
  #define PATCH_ADDR_SIZE 8
#endif

#define MAX_DUMP_FILENAME 256
#define MAX_TRACE_FILENAME 256
#define MAX_OP_PARA_LEN 3
#define MAX_FILE_LINE_LEN 356
#define MAX_CFG_LINE 350

#define CF 5862190	
#define PF 5862619	
#define AF 5862124	
#define ZF 5862949	
#define SF 5862718	
#define DF 5862223	
#define OF 5862586
#define FILENAME_OPT 2089071269

#define MAX_INSTR_COUNT 100000		// max. number of instructions to trace
#define MAX_NUM_DSTS_OP 9			// BUG workaround - TBD Fixed, will remove this after some final checks (popa = 8 DST_OP) 
#define MAX_NUM_SRCS_OP 9			// BUG workaround - TBD Fixed, will remove this after some final checks (pusha = 8 DST_OP)

// --- Typedefs ---
typedef struct p_eflag_para {
	unsigned char* patch_eflag_flag_str;
	reg_t patch_eflag_flag;
	size_t patch_eflag_PC;
	struct p_eflag_para* nextpe;
} P_EFLAG_PARA;

typedef struct p_nop_para {
	size_t patch_nop_start_PC;
	size_t patch_nop_end_PC;
	struct p_nop_para* nextpa;
} P_NOP_PARA;

typedef struct p_call_para {
	size_t patch_call_func_PC;
	size_t patch_call_ret;
	struct p_call_para* nextcp;
} P_CALL_PARA;

typedef struct s_dump_para {
	size_t bufferPC;
	char*  bufferOp;
	int    bufferOpnum;
	char   bufferOptype;
	char   bufferOptypePtrType;

	size_t sizePC;
	char*  sizeOp;
	int    sizeOpnum;
	char   sizeOptype;
	char   sizeOptypePtrType;

	size_t dumpPC;
	char*  filename;
	struct s_dump_para* nextdp;
} S_DUMP_PARA;

typedef struct s_trace_para {
	size_t start;
	size_t end;
	size_t max_instr;
	size_t breakaddress;
	bool   light_trace_only;
	char*  filename;
	file_t fpTracefile;
	struct s_trace_para* nexttr;
} S_TRACE_PARA;

typedef struct s_procs {
	struct s_procs* prevproc;
	process_id_t    start_process_id;
	process_id_t    process_id;
	thread_id_t     threat_id;
	struct s_procs* nextproc;
} S_PROCS;


// --- Functions prototypes ---

// main
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[]);
int parse_cmd_opt();
void event_exit(void);
bool parse_loop_line(char* line, unsigned int linenr);
bool parse_cfgfile(char* filename);
bool parse_patch_flag_line(char* line);
bool parse_patch_nop_line(char* line);
bool parse_patch_call_line(char* line);
bool parse_dump_buffer_line(char* line, unsigned int linenr);
bool parse_trace_line(char* line, unsigned int linenr);

// ddr_helper_functions
void usage();
bool CheckFileExists(const CHAR* fileName);
char* getSubstr(char* str, char* p1, char* p2);
char* escape_filename(char* filename);
int escape_dir_str(char* dirStr);
bool getOEPfromPEfile(char* pefile, app_pc* oep);
void __cdecl print_disasm(void* drcontext, app_pc instr_addr, size_t instr_addr_fixed);
unsigned long djb2_hash(unsigned char* str);
unsigned char* strtoupper(unsigned char* t);
void check_strlen(char* str, size_t maxlen, char* failmsg, unsigned int linenr);
bool fix_comma_in_jsonfile(char* fname);

// trace_instr
void event_module_load_trace_instr(void* drcontext, const module_data_t* info, bool loaded);
void event_thread_init_trace_instr(void* drcontext);
void event_thread_exit_trace_instr(void* drcontext);
//void __cdecl process_instr_trace_instr(app_pc instr_addr);
void __cdecl process_instr_trace_instr_new(app_pc instr_addr, S_TRACE_PARA* tr);
static void iterate_exports_trace_instr(const module_data_t* info);
static bool lib_is_not_blacklisted_trace_instr(const module_data_t* info);
static unsigned char* get_byte_string_trace_instr(unsigned char* bytesbuf, size_t bytesread);
static void log_bytestream_trace_instr(file_t f, unsigned char* bytesbuf, size_t bytesread, app_pc memaddr, uint instr_mem_size);
static bool write_mem_data_trace_instr(file_t f, size_t numbytes, app_pc memaddr, char* json_field_str);
static bool write_mem_to_file_trace_instr(file_t f, ssize_t numbytes, app_pc memaddr);
static void write_src_op_to_logfile_trace_instr(file_t f, instr_t* instr, app_pc memaddr_src0, size_t bytesread, size_t numbytes);
static void log_instr_opnds_trace_instr(file_t f, instr_t* instr, dr_mcontext_t* mc, void* drcontext, size_t numbytes);
static void log_mem_at_reg_trace_instr(app_pc memaddr, char* regstr, file_t f);
static void handler_instr_is_return(file_t f, instr_t* instr, dr_mcontext_t* mc, size_t numbytes);
static void handler_instr_is_call(file_t f, instr_t* instr, dr_mcontext_t* mc, size_t numbytes);
static void handler_instr_is_pop(file_t f, instr_t* instr, dr_mcontext_t* mc, size_t numbytes);
static void handler_instr_interesting_instr(file_t f, instr_t* instr, dr_mcontext_t* mc, size_t numbytes);
static void handler_all_other_mem_instr(file_t f, instr_t* instr, dr_mcontext_t* mc, size_t numbytes);

// dump_buffer
void my_call_pre_wrapper(void* wrapcxt, OUT void** user_data);
void event_thread_init_global(void* drcontext);
int __cdecl get_mem_addr_dump_buffer(void* drcontext, reg_t* memaddr, char Optype, char OptypePtrType, int Opnum, app_pc instr_addr, dr_mcontext_t mc);
int __cdecl get_op_size_dump_buffer(void* drcontext, reg_t* memaddr, char Optype, char OptypePtrType, int Opnum, app_pc instr_addr, dr_mcontext_t mc);
dr_emit_flags_t event_bb_instr_global(void* drcontext, void* tag, instrlist_t* bb, instr_t* instr, bool for_trace, bool translating, void* user_data);
void __cdecl process_instr_size_dump_buffer(app_pc instr_addr, S_DUMP_PARA* dp);
void __cdecl process_instr_addr_dump_buffer(app_pc instr_addr, S_DUMP_PARA* dp);
void __cdecl process_instr_dump_buffer(app_pc instr_addr, S_DUMP_PARA* dp);

// patch_exe
void __cdecl patch_eflag(app_pc instr_addr, P_EFLAG_PARA* pp);
void __cdecl patch_sleep(app_pc instr_addr);
