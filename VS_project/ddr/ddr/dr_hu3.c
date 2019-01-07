/*
-------------------------------------------------------------------------------
 
DDR IDA Pro Plug-in: Dynamic Data Resolver(DDR) backend DLL
Version 0.1 alpha
Copyright(C) 2019 Cisco Talos
Author: Holger Unterbrink(hunterbr@cisco.com)

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

Usage:
drrun.exe -c <DDR.DLL> -s <START_ADDR> -e <END_ADDR> -f <FILENAME> [ -c <COUNT> -b <BREAK_ADDR> -t ] -- <SAMPLE.EXE>

-s <START_ADDR>         Start address for logging dynamic data
-s <END_ADDR>           End address for logging dynamic data
-f <FILENAME>           JSON log filename
-c <COUNT>              Count of instructions to log between START_ADDR and END_ADDR
-b <BREAK_ADDR>         hard break at BREAK_ADDR. No exit/cleanup functions are executed
-t                      Don't create full trace, just log the instruction address into a JSON file
<SAMPLE.EXE>            Sample PE file to analyse

e.g. 
C:\DYNRIO_DIR\bin64\drrun.exe -c "C:\ddr\ddr64.dll" -s 0x140001000 -e 0x140002200 -c 10000 -f "C:\ddrlog\sample_log64.json" -- sample64.exe

C:\DYNRIO_DIR\bin32\drrun.exe -c "C:\ddr\ddr32.dll" -s 0x00401000 -e 0x00402000   -c 10000 -f "C:\ddrlog\sample_log32.json" -- sample32.exe

x64 sample:
C:\tools\DynamoRIO-Windows-7.0.0-RC1\bin64\drrun.exe -c "C:\Users\Dex Dexter\Documents\Visual Studio 2017\Projects\ddr\x64\Release\ddr.dll"
-s 0x140001000 -e 0x140002200 -c 10000 -f "C:\tools\test64.json" --
"C:\Users\Dex Dexter\Documents\Visual Studio 2017\Projects\hello_world\x64\Release\hello_world.exe"

x32 sample:
C:\tools\DynamoRIO-Windows-7.0.0-RC1\bin32\drrun.exe -c "C:\Users\Dex Dexter\documents\visual studio 2017\Projects\ddr\Release\ddr.dll"
-s 0x00401000 -e 0x00402000 -c 10000 -f "C:\tools\test32.json" --
"C:\Users\Dex Dexter\documents\visual studio 2017\Projects\hello_world\Release\hello_world.exe"

*/

#include "dr_api.h"
#include "drmgr.h"
#include "utils.h"
#include "drreg.h"
#include "drx.h"
#include "drwrap.h"
#include <windows.h>
#include <malloc.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_INSTR_COUNT 100000		// max. number of instructions to trace
#define MAX_NUM_DSTS_OP 4	// BUG workaround - TBD Fixed, remove this
#define MAX_NUM_SRCS_OP 4	// BUG workaround - TBD Fixed, remove this

static void event_exit(void);
static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);

static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag,
	instrlist_t *bb, instr_t *instr,
	bool for_trace, bool translating,
	void *user_data);

static int tls_idx;
static int tls_idx2;
static client_id_t my_id;
size_t oep_diff;
size_t ref_flags;
size_t from_addr = (size_t)NULL;
size_t to_addr = (size_t)NULL;
size_t break_addr = (size_t)NULL;
size_t inst_count = MAX_INSTR_COUNT;
size_t inst_num = 0;
bool trace_only = FALSE;
bool first_instr_set = TRUE;
bool OEP_moved_plus = FALSE;

int escape_dir_str(char *dirStr)
{
	int count;
	size_t SearchStrLen;
	size_t ReplaceStrLen;
	char *sp; 
	const char *search = "\\";
	const char *replace = "\\\\";

	if ((sp = strstr(dirStr, search)) == NULL) {
		return(0);
	}
	count = 1;
	SearchStrLen = strlen(search);
    ReplaceStrLen = strlen(replace);
	if (SearchStrLen > ReplaceStrLen) {
		char *src = sp + SearchStrLen;
		char *dst = sp + ReplaceStrLen;
		while ((*dst = *src) != '\0') { dst++; src++; }
	}
	else if (SearchStrLen < ReplaceStrLen) {
		size_t tmpLen = strlen(sp) - SearchStrLen;
		char *stop = sp + ReplaceStrLen;
		char *src = sp + SearchStrLen + tmpLen;
		char *dst = sp + ReplaceStrLen + tmpLen;
		while (dst >= stop) { *dst = *src; dst--; src--; }
	}
	memcpy(sp, replace, ReplaceStrLen);

	//interate through string
	count += escape_dir_str(sp + ReplaceStrLen); 

	return(count);
}

void usage()
{
	dr_printf("\n");
	dr_printf("Usage:\n");
	dr_printf("drrun.exe -c <DDR.DLL> -s <START_ADDR> -e <END_ADDR> -f <FILENAME> [ -c <COUNT> -b <BREAK_ADDR> -t ] -- <SAMPLE.EXE>\n\n");
	dr_printf("-s <START_ADDR>         Start address for logging dynamic data\n");
	dr_printf("-s <END_ADDR>           End address for logging dynamic data\n");
	dr_printf("-f <FILENAME>           JSON log filename\n");
	dr_printf("-c <COUNT>              Count of instructions to log between START_ADDR and END_ADDR\n");
	dr_printf("-b <BREAK_ADDR>         hard break at BREAK_ADDR. No exit/cleanup functions are executed\n");
	dr_printf("-t                      Don't create full trace, just log the instruction address into a JSON file\n");
	dr_printf("<SAMPLE.EXE>            Sample PE file to analyse\n\n");
    dr_printf("C:\\DYNRIO_DIR\\bin64\\drrun.exe -c \"C:\\ddr\\ddr64.dll\" -s 0x140001000 -e 0x140002200 -c 10000 -f \"C:\\ddrlog\\sample_log64.json\" -- sample64.exe\n");
	dr_printf("C:\\DYNRIO_DIR\\bin32\\drrun.exe -c \"C:\\ddr\\ddr32.dll\" -s 0x00401000 -e 0x00402000   -c 10000 -f \"C:\\ddrlog\\sample_log32.json\" -- sample32.exe\n\n");
}

char *parse_cmd_opt() {

	int argc;
	char **argv;
	char *filename = (char *) NULL;

	bool tstart_set = FALSE;
	bool tend_set = FALSE;
	bool tbreak_set = FALSE;
	bool num_instr_set = FALSE;
	bool fname_set = FALSE;

	dr_get_option_array(my_id, &argc, &argv);

	int i;
	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-s")) {
			from_addr = (size_t)strtoull(argv[i + 1], NULL, 16);
			tstart_set = TRUE;
		}

		if (!strcmp(argv[i], "-e")) {
			to_addr = (size_t)strtoull(argv[i + 1], NULL, 16);
			tend_set = TRUE;
		}

		if (!strcmp(argv[i], "-c")) {
			inst_count = (size_t)strtoull(argv[i + 1], NULL, 10); // TBD size checks
			num_instr_set = TRUE;
		}

		if (!strcmp(argv[i], "-b")) {
			break_addr = (size_t)strtoull(argv[i + 1], NULL, 16);
			tbreak_set = TRUE;
		}
		if (!strcmp(argv[i], "-f")) {
			filename = argv[i + 1];
			fname_set = TRUE;
		}
		if (!strcmp(argv[i], "-t")) {
			trace_only = TRUE;
		}
	}

	if (!tstart_set) {
		dr_printf("ERROR: you need to set a start address (-s).\n");
		usage();
		dr_exit_process(1);
	}

	if (!tend_set) {
		dr_printf("ERROR: you need to set an end address (-e).\n");
		usage();
		dr_exit_process(1);
	}

	if (!fname_set) {
		dr_printf("ERROR: you need to set a log filename (-f).\n");
		usage();
		dr_exit_process(1);
	}

	return filename;
}

static void iterate_exports(const module_data_t *info)
{
	file_t api_json_f = (file_t)(ptr_uint_t)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx2);

	dr_symbol_export_iterator_t *exp_iter =
		dr_symbol_export_iterator_start(info->handle);
	while (dr_symbol_export_iterator_hasnext(exp_iter)) {
		dr_symbol_export_t *sym = dr_symbol_export_iterator_next(exp_iter);
		if ((sym->is_code) && (sym->addr != NULL)) {
			dr_fprintf(api_json_f, "  {\"address\"    : \""PFX"\",\n", sym->addr);
			dr_fprintf(api_json_f, "   \"name\"       : \"%s\",\n", sym->name);
			dr_fprintf(api_json_f, "   \"module\"     : \"%s\"},\n", dr_module_preferred_name(info));
		}
	}
	dr_symbol_export_iterator_stop(exp_iter);
}

bool lib_is_not_blacklisted(const module_data_t *info) {

	char *blacklist[] = { "dynamorio.dll", "drmgr.dll", "ddr.dll", NULL };
	int i = 0;
	while (blacklist[i]) {
		if (strstr(dr_module_preferred_name(info), blacklist[i++]) != NULL)
			return FALSE;
	}
	return TRUE;
}

static void event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
	//dr_printf("Module loaded: %s:\n", dr_module_preferred_name(info));
	if (lib_is_not_blacklisted(info))
		iterate_exports(info);
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
	dr_set_client_name("DynamoRIO DDR tracer", "https://talosintelligence.com/");
	drmgr_init();
	my_id = id;

	disassemble_set_syntax(DR_DISASM_INTEL);

	dr_enable_console_printing();
	//dr_log(NULL, LOG_ALL, 1, "Client initializing...\n");
	dr_printf("\nClient initializing...\n");

	dr_register_exit_event(event_exit);

	// only analyse API calls if we are not in trace only mode 
	if (!trace_only) {
		drmgr_register_module_load_event(event_module_load);
	}

	drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
	drmgr_register_thread_init_event(event_thread_init);
	drmgr_register_thread_exit_event(event_thread_exit);

	tls_idx = drmgr_register_tls_field();
	DR_ASSERT(tls_idx > -1);
	tls_idx2 = drmgr_register_tls_field();
	DR_ASSERT(tls_idx > -1);
}

static void event_exit(void)
{
	drmgr_unregister_tls_field(tls_idx);
	drmgr_unregister_tls_field(tls_idx2);
	drmgr_exit();
}

bool getOEPfromPEfile(char *pefile, app_pc *oep) {

	FILE *fp;
	errno_t err;
	err = fopen_s(&fp, pefile, "rb");
	if (err != 0) {
		dr_printf("ERROR:Failed opening PE file\n", pefile);
		return FALSE;
	}
	fseek(fp, 0, SEEK_SET);

	IMAGE_DOS_HEADER imgDosHdr;
	fread(&imgDosHdr, sizeof(IMAGE_DOS_HEADER), 1, fp);

	fseek(fp, imgDosHdr.e_lfanew, SEEK_SET);
	IMAGE_NT_HEADERS imgNtHdr;
	fread(&imgNtHdr, sizeof(IMAGE_NT_HEADERS), 1, fp);

	*oep = (app_pc)(imgNtHdr.OptionalHeader.ImageBase + imgNtHdr.OptionalHeader.AddressOfEntryPoint);

	fclose(fp);
	return TRUE;
}

static void event_thread_init(void *drcontext)
{
	file_t f, api_json_f;
	app_pc FileEntryPoint, PEEntryPoint, PEImagebase;
	module_data_t *app;

	char *LogFilename; 
	char *samplename;
	char samplename_cleaned[MAX_PATH*2];
	char api_logfile[MAX_PATH];
	char *stmp;

	// Parse cmd line arguments. TBD more input checks.
	LogFilename = parse_cmd_opt();
	if (strlen(LogFilename) >= MAX_PATH - strlen("_apicalls.json")) {
		dr_printf("ERROR: Logfilename is too long.\n");
		dr_exit_process(1);
	}

	dr_printf("Using instruction logfile: %s\n", LogFilename); 
	
	// Open instruction log file.  
	f = dr_open_file(LogFilename, DR_FILE_WRITE_OVERWRITE);
	DR_ASSERT(f != INVALID_FILE);
	drmgr_set_tls_field(drcontext, tls_idx, (void *)(ptr_uint_t)f);

	// Open api call log file. 
	if (!trace_only) {
		strcpy_s(api_logfile, MAX_PATH, LogFilename);
		stmp = strrchr(api_logfile, '.');
		if (stmp != NULL)
			*stmp = '\0';
		strcat_s(api_logfile, MAX_PATH, "_apicalls.json");
		dr_printf("Using API calls logfile: %s\n", api_logfile);
		api_json_f = dr_open_file(api_logfile, DR_FILE_WRITE_OVERWRITE);
		DR_ASSERT(f != INVALID_FILE);

		drmgr_set_tls_field(drcontext, tls_idx2, (void *)(ptr_uint_t)api_json_f);
		dr_fprintf(api_json_f, "{\n\"apicalls\" :\n [\n");
	}

	// Get sample Filename  
	app = dr_get_main_module();
	samplename = app->full_path;
	if (strlen(samplename) > MAX_PATH) {
		dr_printf("ERROR: Filename path too long\n");
		dr_exit_process(1);
	}
	else {
		memcpy(samplename_cleaned, samplename, strlen(samplename));
		samplename_cleaned[strlen(samplename)] = '\0';
	}
	// escape filename string for JSON file
	if (!escape_dir_str(samplename_cleaned)) {
		dr_printf("ERROR: Failed to escape file path\n");
		dr_exit_process(1);
	}
	
	// Write meta data about the sample into the logfile
	// TBD: use a proper JSON lib instead
	dr_fprintf(f, "{\n\"samplename\"             : \"%s\",\n", samplename_cleaned ? samplename_cleaned : "FILENAME_PARSING_ERROR");	

	#ifdef X86_64
		dr_fprintf(f, "\"architecture\"           : \"x64\",\n");
	#else
		dr_fprintf(f, "\"architecture\"           : \"x32\",\n");	
	#endif

	dr_fprintf(f, "\"trace_start\"            : \""PFX"\",\n", from_addr);
	dr_fprintf(f, "\"trace_end\"              : \""PFX"\",\n", to_addr);
	dr_fprintf(f, "\"num_instr_to_trace\"     : \"%d\",\n", inst_count);

	byte* peb = dr_get_app_PEB();

	PEEntryPoint = app->entry_point;
	PEImagebase  = app->start;
	dr_printf("PE Imagebase  = "PFX"\n", PEImagebase);
	dr_printf("PE Entrypoint = "PFX"\n", PEEntryPoint);
	dr_printf("PEB           = "PFX"\n", peb);

	// get OEP from orginal file on disk
	if (!getOEPfromPEfile(samplename, &FileEntryPoint)) {
		dr_printf("WARNING: OEP not found in file.\n");
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
	
	dr_fprintf(f, "\"peb\"                    : \""PFX"\",\n", peb);
	dr_fprintf(f, "\"imagebase\"              : \""PFX"\",\n", PEImagebase);
	dr_fprintf(f, "\"entrypoint\"             : \""PFX"\",\n", PEEntryPoint);
	dr_fprintf(f, "\"oep\"                    : \""PFX"\",\n", FileEntryPoint);
	dr_fprintf(f, "\"oep_diff\"               : \""PFX"\",\n", oep_diff);
	dr_fprintf(f, "\"break_addr\"             : \""PFX"\",\n", break_addr ? break_addr : 0);
	dr_fprintf(f, "\"instruction\"            : \n[\n");

	dr_free_module_data(app);

	dr_printf("\nSample output:\n");
	dr_printf("--------------\n");
}

static void event_thread_exit(void *drcontext)
{
	file_t f  = (file_t)(ptr_uint_t)drmgr_get_tls_field(drcontext, tls_idx);
	file_t api_json_f;

	if (trace_only) {
		// Delete last comma
		dr_file_seek(f, -2, DR_SEEK_CUR);
		dr_fprintf(f, "\n");
	}
	dr_fprintf(f, " ]\n}\n");
	dr_close_file(f);

	if (!trace_only) {
		api_json_f = (file_t)(ptr_uint_t)drmgr_get_tls_field(drcontext, tls_idx2);
		dr_file_seek(api_json_f, -2, DR_SEEK_CUR);
		dr_fprintf(api_json_f, "\n ]\n}\n");
		dr_close_file(api_json_f);
	}

	dr_printf("\nDone. Sample executed.\n");

}

static unsigned char* getByteString(unsigned char *bytesbuf, size_t bytesread) {

	if (bytesread < 1) return NULL;

	unsigned int i;
	unsigned char *bytestr = (unsigned char *)dr_global_alloc(sizeof(unsigned char) * (bytesread * 3 + 1));
	unsigned char *bytestr_tmp = bytestr;
	unsigned char c;
	for (i = 0; i < bytesread; i++) {
		c = *(bytesbuf + i);
		dr_snprintf(bytestr_tmp, 4, "%02x ", c);
		bytestr_tmp += 3;
	}
	unsigned char *charstr = (unsigned char *)dr_global_alloc(sizeof(unsigned char) * (bytesread + 1));
	unsigned char *charstr_tmp = charstr;
	for (i = 0; i < bytesread; i++) {
		c = *(bytesbuf + i);
		if ((c <127) && (c >31) && (c != 92) && (c != 34)) // exclude '\'=92 and "=34 for JSON comp. 
			dr_snprintf(charstr_tmp++, 2, "%c", c);
		else
			dr_snprintf(charstr_tmp++, 2, ".");
	}

	size_t resultstr_size = strlen(bytestr) + strlen(charstr) + 3 + 1; //3 spaces in snprintf below
	unsigned char *resultstr = (unsigned char *)dr_global_alloc(sizeof(unsigned char) * resultstr_size);
	dr_snprintf(resultstr, resultstr_size, "%s   %s", bytestr, charstr);

	dr_global_free(bytestr, sizeof(unsigned char) * (bytesread * 3 + 1));
	dr_global_free(charstr, sizeof(unsigned char) * (bytesread + 1));

	return resultstr;
}

static void log_bytestream(file_t f, unsigned char *bytesbuf, size_t bytesread, app_pc memaddr, uint instr_mem_size) {

	char *bytesstr = getByteString(bytesbuf, bytesread);

	if (bytesstr) {
		dr_fprintf(f, "  \"inst_mem_addr\"  : \""PFX"\",\n", memaddr);
		dr_fprintf(f, "  \"inst_mem_size\"  : \""PFX"\",\n", instr_mem_size);
		dr_fprintf(f, "  \"inst_mem_data\"  : \"%s\",\n", bytesstr);
		dr_global_free(bytesstr, strlen(bytesstr) + 1);
	}
	else {
		dr_fprintf(f, "  \"inst_mem_addr\"  : \""PFX"\",\n", memaddr);
		dr_fprintf(f, "  \"inst_mem_size\"  : \""PFX"\",\n", instr_mem_size);
		dr_fprintf(f, "  \"inst_mem_data\"  : \"NOT_DECODED\",\n");
	}
}

static void handler_instr_is_return(file_t f, instr_t *instr, dr_mcontext_t *mc, size_t numbytes) {
	return;
}

static void handler_instr_is_call(file_t f, instr_t *instr, dr_mcontext_t *mc, size_t numbytes) {
	return;
}

static void handler_instr_is_pop(file_t f, instr_t *instr, dr_mcontext_t *mc, size_t numbytes) {
	return;
}

static void handler_instr_interesting_instr(file_t f, instr_t *instr, dr_mcontext_t *mc, size_t numbytes) {
	opnd_t op = instr_get_src(instr, 0);
	app_pc memaddr = opnd_compute_address(op, mc);
	size_t bytesread;

	uint instr_mem_size = instr_memory_reference_size(instr);

	char *bytesbuf = (char *)dr_global_alloc(sizeof(char) * numbytes);
	dr_safe_read(memaddr, numbytes, bytesbuf, &bytesread);

	log_bytestream(f, bytesbuf, bytesread, memaddr, instr_mem_size);

	dr_global_free(bytesbuf, sizeof(char) * numbytes);
	return;
}

static void handler_all_other_mem_instr(file_t f, instr_t *instr, dr_mcontext_t *mc, size_t numbytes) {

	opnd_t op = instr_get_src(instr, 0);
	app_pc memaddr = opnd_compute_address(op, mc);
	size_t bytesread;

	uint instr_mem_size = instr_memory_reference_size(instr);

	char *bytesbuf = (char *)dr_global_alloc(sizeof(char) * numbytes);
	dr_safe_read(memaddr, numbytes, bytesbuf, &bytesread);

	log_bytestream(f, bytesbuf, bytesread, memaddr, instr_mem_size);

	dr_global_free(bytesbuf, sizeof(char) * numbytes);

	return;
}

static bool writeMemData(file_t f, size_t numbytes, app_pc memaddr, char *json_field_str) {
	char * bytesbuf, *bytesstr;
	size_t bytesread;

	bytesbuf = (char *)dr_global_alloc(sizeof(char) * numbytes);
	dr_safe_read(memaddr, numbytes, bytesbuf, &bytesread);

	bytesstr = getByteString(bytesbuf, bytesread);
	if (bytesstr) {
		// only add to JSON file if not NULL
		dr_fprintf(f, ",\n");
		dr_fprintf(f, "  \"%s\"  : \"%s\"", json_field_str, bytesstr);
		dr_global_free(bytesstr, sizeof(char) * (strlen(bytesstr) + 1));
		if (bytesbuf) dr_global_free(bytesbuf, sizeof(char) * numbytes);
		return TRUE;
	}
	else {
		if (bytesstr) dr_global_free(bytesstr, sizeof(char) * (strlen(bytesstr) + 1));
		if (bytesbuf) dr_global_free(bytesbuf, sizeof(char) * numbytes);
		return FALSE;
	}
}
static void writeSrcOpToLogfile(file_t f, instr_t *instr, app_pc memaddr_src0, size_t bytesread, size_t numbytes) {

	size_t memaddr_src0_ptr;

	//dr_fprintf(f, "  \"inst_mem_instr_opname\"  : \"%s\",\n", decode_opcode_name(instr_get_opcode(instr)));
	dr_fprintf(f, "  \"inst_mem_addr_src0\"  : \""PFX"\"", memaddr_src0);
	writeMemData(f, numbytes, memaddr_src0, "inst_mem_addr_src0_data");
	dr_safe_read(memaddr_src0, sizeof(size_t), &memaddr_src0_ptr, &bytesread);
	dr_fprintf(f, ",\n  \"inst_mem_addr_src0_data_ptr\"  : \""PFX"\"", memaddr_src0_ptr);
	writeMemData(f, numbytes, (app_pc)memaddr_src0_ptr, "inst_mem_addr_src0_data_ptr_data");

}

static void logMemAtInstrOPs(file_t f, instr_t *instr, dr_mcontext_t *mc, void *drcontext, size_t numbytes) {

	int    num_dsts = 0, num_srcs = 0;
	opnd_t opnd_src0, opnd_dst0;
	app_pc memaddr_src0, memaddr_dst0;
	size_t memaddr_src0_ptr, memaddr_dst0_ptr;
	size_t bytesread;
	reg_id_t reg;

	num_dsts = instr_num_dsts(instr);
	num_srcs = instr_num_srcs(instr);

	// handle memory access of special instructions 

	// direct call
	if (instr_is_call_direct(instr)) {
		opnd_src0 = instr_get_src(instr, 0);

		if (opnd_is_reg(opnd_src0)) {
			reg = opnd_get_reg(opnd_src0);
			memaddr_src0 = (app_pc)reg_get_value(reg, mc);
		}
		else {
			memaddr_src0 = opnd_get_pc(opnd_src0);
		}
		writeSrcOpToLogfile(f, instr, memaddr_src0, bytesread, numbytes);
		return;
	}
	// indirect call
	if (instr_is_call_indirect(instr)) {
		opnd_src0 = instr_get_src(instr, 0);
		if (opnd_is_reg(opnd_src0)) {
			reg = opnd_get_reg(opnd_src0);
			memaddr_src0 = (app_pc)reg_get_value(reg, mc);
		}
		else {
			memaddr_src0 = opnd_compute_address(opnd_src0, mc);
		}
		writeSrcOpToLogfile(f, instr, memaddr_src0, bytesread, numbytes);
		return;
	}
	// conditional branch
	if (instr_is_cbr(instr)) {
		opnd_src0 = instr_get_src(instr, 0);
		memaddr_src0 = opnd_get_pc(opnd_src0);
		writeSrcOpToLogfile(f, instr, memaddr_src0, bytesread, numbytes);
		return;
	}
	// push
	if (instr_get_opcode(instr) == OP_push || instr_get_opcode(instr) == OP_push_imm) {
		opnd_src0 = instr_get_src(instr, 0);

		// operant is register
		if (opnd_is_reg(opnd_src0)) {
			reg = opnd_get_reg(opnd_src0);
			memaddr_src0 = (app_pc)reg_get_value(reg, mc);  //TBD check typecast
			writeSrcOpToLogfile(f, instr, memaddr_src0, bytesread, numbytes);
			return;
		}
		// anyhing else
		else {
			memaddr_src0 = opnd_compute_address(opnd_src0, mc);
			writeSrcOpToLogfile(f, instr, memaddr_src0, bytesread, numbytes);
			return;
		}
	}

	// CMP
	if (instr_get_opcode(instr) == OP_cmp) {
		dr_fprintf(f, "  \"inst_mem_instr_opname_cmp\"  : \"%s\",\n", decode_opcode_name(instr_get_opcode(instr)));
		
		opnd_src0 = instr_get_src(instr, 0);
		opnd_dst0 = instr_get_src(instr, 1);

		// src operant is register
		if (opnd_is_reg(opnd_src0)) {
			reg = opnd_get_reg(opnd_src0);
			memaddr_src0 = (app_pc)reg_get_value(reg, mc);  //TBD check typecast
			dr_fprintf(f, "  \"inst_mem_addr_src0\"     : \""PFX"\"", memaddr_src0);
			writeMemData(f, numbytes, memaddr_src0, "inst_mem_addr_src0_data");
			dr_fprintf(f, ",\n");
		}
		// src operant is anyhing else
		else {
			memaddr_src0 = opnd_compute_address(opnd_src0, mc);
			dr_fprintf(f, "  \"inst_mem_addr_src0\"     : \""PFX"\"", memaddr_src0);
			writeMemData(f, numbytes, memaddr_src0, "inst_mem_addr_src0_data");
			dr_fprintf(f, ",\n");
		}
		
		// dst operant is register
		if (opnd_is_reg(opnd_dst0)) {
			reg = opnd_get_reg(opnd_dst0);
			memaddr_dst0 = (app_pc)reg_get_value(reg, mc);  //TBD check typecast
			dr_fprintf(f, "  \"inst_mem_addr_dst0\"     : \""PFX"\"", memaddr_dst0);
			writeMemData(f, numbytes, memaddr_dst0, "inst_mem_addr_dst0_data");
			return;
		}
		// dst operant is anyhing else
		else {
			memaddr_dst0 = opnd_compute_address(opnd_dst0, mc);
			dr_fprintf(f, "  \"inst_mem_addr_dst0\"     : \""PFX"\"", memaddr_dst0);
			writeMemData(f, numbytes, memaddr_dst0, "inst_mem_addr_dst0_data");
			return;
		}
	}

	// all other instructions
	if (((num_dsts > 0) && (num_dsts < MAX_NUM_DSTS_OP)) || (num_srcs > 0) && (num_dsts < MAX_NUM_SRCS_OP))
		dr_fprintf(f, "  \"inst_mem_instr_opname\"  : \"%s\",\n", decode_opcode_name(instr_get_opcode(instr)));
	else
		dr_fprintf(f, "  \"inst_mem_instr_opname\"  : \"%s\"", decode_opcode_name(instr_get_opcode(instr)));

	// destination operant
	if ((num_dsts > 0) && (num_dsts < MAX_NUM_DSTS_OP)) {  // '&& num_dsts < 3' covers dynamoRio bug

		opnd_dst0 = instr_get_dst(instr, 0);

		// op is register
		if (opnd_is_reg(opnd_dst0)) {
			reg = opnd_get_reg(opnd_dst0);
			memaddr_dst0 = (app_pc)reg_get_value(reg, mc);
			dr_fprintf(f, "  \"inst_mem_addr_dst0\"  : \""PFX"\"", memaddr_dst0);
			writeMemData(f, numbytes, memaddr_dst0, "inst_mem_addr_dst0_data");
		}
		// op is not a register
		else {
			memaddr_dst0 = opnd_compute_address(opnd_dst0, mc);
			dr_fprintf(f, "  \"inst_mem_addr_dst0\"  : \""PFX"\"", memaddr_dst0);
			writeMemData(f, numbytes, memaddr_dst0, "inst_mem_addr_dst0_data");
		}

		// the op is a memory reference
		if (opnd_is_memory_reference(opnd_dst0)) {
			dr_fprintf(f, ",\n");
			dr_safe_read(memaddr_dst0, sizeof(size_t), &memaddr_dst0_ptr, &bytesread);
			dr_fprintf(f, "  \"inst_mem_addr_dst0_data_ptr\"  : \""PFX"\"", memaddr_dst0_ptr);
			writeMemData(f, numbytes, (app_pc)memaddr_dst0_ptr, "inst_mem_addr_dst0_data_ptr_data");
		}

	}
	// source operant
	if ((num_srcs > 0) && (num_dsts < MAX_NUM_SRCS_OP)) { // '&& num_dsts < 3' covers dynamoRio bug
		if (num_dsts > 0)
			dr_fprintf(f, ",\n");

		opnd_src0 = instr_get_src(instr, 0);

		// op is register
		if (opnd_is_reg(opnd_src0)) {
			reg = opnd_get_reg(opnd_src0);
			memaddr_src0 = (app_pc)reg_get_value(reg, mc);
			dr_fprintf(f, "  \"inst_mem_addr_src0\"  : \""PFX"\"", memaddr_src0);
			writeMemData(f, numbytes, memaddr_src0, "inst_mem_addr_src0_data");
		}
		// op is not a register
		else {
			memaddr_src0 = opnd_compute_address(opnd_src0, mc);
			dr_fprintf(f, "  \"inst_mem_addr_src0\"  : \""PFX"\"", memaddr_src0);
			writeMemData(f, numbytes, memaddr_src0, "inst_mem_addr_src0_data");
		}

		// the op is a memory reference
		if (opnd_is_memory_reference(opnd_src0)) {
			dr_fprintf(f, ",\n");
			dr_safe_read(memaddr_src0, sizeof(size_t), &memaddr_src0_ptr, &bytesread);
			dr_fprintf(f, "  \"inst_mem_addr_src0_data_ptr\"  : \""PFX"\"", memaddr_src0_ptr);
			writeMemData(f, numbytes, (app_pc)memaddr_src0_ptr, "inst_mem_addr_src0_data_ptr_data");
		}

		// --- Code for detecting an DynamoRIO bug with instr_t init ---
		if (num_dsts > MAX_NUM_DSTS_OP - 1) {
			dr_fprintf(f, ",\n");
			dr_fprintf(f, "  \"inst_mem_addr_dst0_fail\"  : \"DR_BUG_DETECTED\",\n");
			dr_fprintf(f, "  \"inst_mem_addr_dst0_num_dsts\"  : \"%d\"", num_dsts);
			num_dsts = 0;
		}
		if (num_srcs > MAX_NUM_SRCS_OP - 1) {
			dr_fprintf(f, ",\n");
			if (num_dsts > 2) dr_fprintf(f, ",\n");
			dr_fprintf(f, "  \"inst_mem_addr_src0_fail\"  : \"DR_BUG_DETECTED\",\n");
			dr_fprintf(f, "  \"inst_mem_addr_src0_num_dsts\"  : \"%d\"", num_srcs);
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

static void logMemAtReg(app_pc memaddr, char * regstr, file_t f) {

	size_t bytesread;
	size_t bytesbuf_len = 16;
	char *bytesstr;
	char *bytesbuf = (char *)dr_global_alloc(sizeof(char) * bytesbuf_len);

	if (dr_safe_read(memaddr, 16, bytesbuf, &bytesread)) {

		bytesstr = getByteString(bytesbuf, bytesread);

		if (bytesstr) {
			dr_fprintf(f, "  \"%s_ptr_data\"  : \"%s\",\n", regstr, bytesstr);
			dr_global_free(bytesstr, strlen(bytesstr) + 1);
			dr_global_free(bytesbuf, bytesbuf_len);
			return;
		}
	}
	dr_fprintf(f, "  \"%s_ptr_data\"  : \"NO_DATA\",\n", regstr);
}

static void __cdecl process_instr(app_pc instr_addr)
{
	char *cf_bit = "cf=0";
	char *pf_bit = "pf=0";
	char *af_bit = "af=0";
	char *zf_bit = "zf=0";
	char *sf_bit = "sf=0";
	char *df_bit = "df=0";
	char *of_bit = "of=0";

	size_t instr_addr_fixed;

	void *drcontext;
	byte *pc;

	file_t f = (file_t)(ptr_uint_t)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);

	drcontext = dr_get_current_drcontext();
	dr_mcontext_t mc = { sizeof(mc),DR_MC_ALL };
	dr_get_mcontext(drcontext, &mc);

	if (!OEP_moved_plus)
		instr_addr_fixed = (size_t)instr_addr + oep_diff;
	else
		instr_addr_fixed = (size_t)instr_addr - oep_diff;

	if (instr_addr_fixed == break_addr) {
		event_thread_exit(dr_get_current_drcontext());
		dr_abort();  // does not call any exit routines, just kills the process
	}

	if (inst_count <= 0) {
		dr_printf("WARNING: Max. number of instructions reached. Logging stopped at 0x%x. (-c).\n", instr_addr);
		dr_exit_process(0);  // calls exit routines
	}
	

	if ((instr_addr_fixed >= from_addr) && (instr_addr_fixed <= to_addr)) {

		//drcontext = dr_get_current_drcontext();
		instr_t instr;
		instr_init(drcontext, &instr);
		instr_reset(drcontext, &instr);
	
		if (trace_only) {
			dr_fprintf(f, "  { \"address\" : \""PFX"\" },\n", instr_addr_fixed);
			inst_count--;
			instr_free(drcontext, &instr);
		}
		else {

			inst_count--;

			//dr_mcontext_t mc = { sizeof(mc),DR_MC_ALL };
			//dr_get_mcontext(drcontext, &mc);

			pc = decode(drcontext, instr_addr, &instr);
			if (pc == NULL) {
				dr_fprintf(f, "ERROR: Invalid Instruction found! DynamoRIO can't decode instruction\n");
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
				dr_fprintf(f, ",\n");

			dr_fprintf(f, " {\n");
			dr_fprintf(f, "  \"instr_num\" : \"%d\",\n", inst_num++);
			dr_fprintf(f, "  \"address\" : \""PFX"\",\n", instr_addr_fixed);
			dr_fprintf(f, "  \"xax\"     : \""PFX"\",\n", mc.xax);
			logMemAtReg((app_pc)mc.xax, "xax", f);
			dr_fprintf(f, "  \"xbx\"     : \""PFX"\",\n", mc.xbx);
			logMemAtReg((app_pc)mc.xbx, "xbx", f);
			dr_fprintf(f, "  \"xcx\"     : \""PFX"\",\n", mc.xcx);
			logMemAtReg((app_pc)mc.xcx, "xcx", f);
			dr_fprintf(f, "  \"xdx\"     : \""PFX"\",\n", mc.xdx);
			logMemAtReg((app_pc)mc.xdx, "xdx", f);
			dr_fprintf(f, "  \"xsp\"     : \""PFX"\",\n", mc.xsp);
			logMemAtReg((app_pc)mc.xsp, "xsp", f);
			dr_fprintf(f, "  \"xbp\"     : \""PFX"\",\n", mc.xbp);
			logMemAtReg((app_pc)mc.xbp, "xbp", f);
			dr_fprintf(f, "  \"xsi\"     : \""PFX"\",\n", mc.xsi);
			logMemAtReg((app_pc)mc.xsi, "xsi", f);
			dr_fprintf(f, "  \"xdi\"     : \""PFX"\",\n", mc.xdi);
			logMemAtReg((app_pc)mc.xdi, "xdi", f);

#ifdef X86_64
			dr_fprintf(f, "  \"r8\"      : \""PFX"\",\n", mc.r8);
			logMemAtReg((app_pc)mc.r8, "r8", f);
			dr_fprintf(f, "  \"r9\"      : \""PFX"\",\n", mc.r9);
			logMemAtReg((app_pc)mc.r9, "r9", f);
			dr_fprintf(f, "  \"r10\"     : \""PFX"\",\n", mc.r10);
			logMemAtReg((app_pc)mc.r10, "r10", f);
			dr_fprintf(f, "  \"r11\"     : \""PFX"\",\n", mc.r11);
			logMemAtReg((app_pc)mc.r11, "r11", f);
			dr_fprintf(f, "  \"r12\"     : \""PFX"\",\n", mc.r12);
			logMemAtReg((app_pc)mc.r12, "r12", f);
			dr_fprintf(f, "  \"r13\"     : \""PFX"\",\n", mc.r13);
			logMemAtReg((app_pc)mc.r13, "r13", f);
			dr_fprintf(f, "  \"r14\"     : \""PFX"\",\n", mc.r14);
			logMemAtReg((app_pc)mc.r14, "r14", f);
			dr_fprintf(f, "  \"r15\"     : \""PFX"\",\n", mc.r15);
			logMemAtReg((app_pc)mc.r15, "r15", f);
#endif

			dr_fprintf(f, "  \"eflags\"  : \"0x%x\",\n", ref_flags);
			dr_fprintf(f, "  \"cf_bit\"  : \"%s\",\n", cf_bit);
			dr_fprintf(f, "  \"pf_bit\"  : \"%s\",\n", pf_bit);
			dr_fprintf(f, "  \"af_bit\"  : \"%s\",\n", af_bit);
			dr_fprintf(f, "  \"zf_bit\"  : \"%s\",\n", zf_bit);
			dr_fprintf(f, "  \"sf_bit\"  : \"%s\",\n", sf_bit);
			dr_fprintf(f, "  \"df_bit\"  : \"%s\",\n", df_bit);
			dr_fprintf(f, "  \"of_bit\"  : \"%s\",\n", of_bit);

			// Print DISASM of instruction to JSON file 
			size_t disasm_buf_size = 254;
			unsigned char *disasm_buf = (unsigned char *)dr_global_alloc(sizeof(unsigned char) * disasm_buf_size);
			instr_disassemble_to_buffer(dr_get_current_drcontext(), &instr, disasm_buf, disasm_buf_size);
			dr_fprintf(f, "  \"disasm\"  : \"%s\",\n", disasm_buf);
			dr_global_free(disasm_buf, disasm_buf_size);

			logMemAtInstrOPs(f, &instr, &mc, drcontext, 16);
			dr_fprintf(f, "\n");
			dr_fprintf(f, " }");

			instr_free(drcontext, &instr);
		}
	}
}

static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
	bool for_trace, bool translating, void *user_data)
{
	app_pc instr_addr;
	size_t instr_addr_fixed; 

	instr_addr = instr_get_app_pc(instr);

	if (!OEP_moved_plus)
		instr_addr_fixed = (size_t)instr_addr + oep_diff;
	else
		instr_addr_fixed = (size_t)instr_addr - oep_diff;

	if (instr_is_app(instr)) {	
		if ((instr_addr_fixed >= from_addr) && (instr_addr_fixed <= to_addr)) {
			// we don't need the the fp/mmx state itm, so save_fpstate=FALSE
			dr_insert_clean_call(drcontext, bb, instr, process_instr, FALSE, 1, OPND_CREATE_INTPTR(instr_addr));
		}
	}
	return DR_EMIT_DEFAULT;
}
