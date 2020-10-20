#include "ddr.h"
#include "globals.h"

void usage()
{
	// -no_follow_children drrun does not follow into any child processes
	dr_printf("\n");
	dr_printf("Usage:\n");
	dr_printf("drrun.exe -c <DDR.DLL> -c <CFG_FILE> -- <SAMPLE.EXE>\n");
#ifdef _DEBUG
	dr_printf("-d <DEBUG LEVEL>                 Set verbose level for debugging. (0-5)\n");
#endif
	dr_printf("-c <CFG_FILE>                    Set Dump and patching configuration in <CFG_FILE>\n");
	dr_printf("                                 See sample \"ddr_config.cfg\" for details\n");
	dr_printf("<SAMPLE.EXE>                     Sample PE file to analyse\n\n");
	dr_printf("Examples:\n");
	dr_printf("C:\\DYNRIO_DIR\\bin64\\drrun.exe -c \"C:\\ddr\\ddr64.dll\" -c my_x32_config.cfg -- \"C:\\tools\\ddr\\samples\\buffertest.exe\"\n");
	dr_printf("C:\\DYNRIO_DIR\\bin32\\drrun.exe -c \"C:\\ddr\\ddr32.dll\" -c my_x64_config.cfg -- \"C:\\tools\\ddr\\samples\\buffertest.exe\"\n\n");
}

bool CheckFileExists(const CHAR* fileName)
{
	DWORD       fileAttr;
	
	fileAttr = GetFileAttributesA(fileName);
	if (0xFFFFFFFF == fileAttr)
		return false;
	return true;
}

// Get string between substring p1 and p2
char* getSubstr(char* str, char* p1, char* p2)
{
	char* ret;
	char* stmp1 = strstr(str, p1);
	char* stmp2;

	if (stmp1 != NULL)
	{
		size_t slen = strlen(p1);
		stmp2 = strstr(stmp1 + slen, p2);
		if (p2 != NULL)
		{
			size_t mlen = stmp2 - stmp1;
			if (mlen > 1) {
				ret = dr_global_alloc(mlen);
				if (ret != NULL)
				{
					memcpy(ret, stmp1 + 1, mlen - 1);
					ret[mlen - 1] = '\0';
					return ret;
				}
			}
		}
	}
	return NULL;
}

char* escape_filename(char* filename) {
	// --- TBD ---
	return filename;
}

int escape_dir_str(char* dirStr)
{
	int count;
	size_t SearchStrLen;
	size_t ReplaceStrLen;
	char* sp;
	const char* search = "\\";
	const char* replace = "\\\\";

	if ((sp = strstr(dirStr, search)) == NULL) {
		return(0);
	}
	count = 1;
	SearchStrLen = strlen(search);
	ReplaceStrLen = strlen(replace);
	if (SearchStrLen > ReplaceStrLen) {
		char* src = sp + SearchStrLen;
		char* dst = sp + ReplaceStrLen;
		while ((*dst = *src) != '\0') { dst++; src++; }
	}
	else if (SearchStrLen < ReplaceStrLen) {
		size_t tmpLen = strlen(sp) - SearchStrLen;
		char* stop = sp + ReplaceStrLen;
		char* src = sp + SearchStrLen + tmpLen;
		char* dst = sp + ReplaceStrLen + tmpLen;
		while (dst >= stop) { *dst = *src; dst--; src--; }
	}
	memcpy(sp, replace, ReplaceStrLen);

	//interate through string
	count += escape_dir_str(sp + ReplaceStrLen);

	return(count);
}

bool getOEPfromPEfile(char* pefile, app_pc* oep) {

	FILE* fp;
	errno_t err;
	err = fopen_s(&fp, pefile, "rb");
	if (err != 0) {
		dr_printf("[DDR] [ERROR] Failed opening PE file\n", pefile);
		return FALSE;
	}
	if (fp != NULL) {
		fseek(fp, 0, SEEK_SET);
	}
	else {
		dr_printf("[DDR] [ERROR] Failed opening PE file. File pointer invalid.\n", pefile);
		return FALSE;
	}

	IMAGE_DOS_HEADER imgDosHdr;
	fread(&imgDosHdr, sizeof(IMAGE_DOS_HEADER), 1, fp);

	fseek(fp, imgDosHdr.e_lfanew, SEEK_SET);
	IMAGE_NT_HEADERS imgNtHdr;
	fread(&imgNtHdr, sizeof(IMAGE_NT_HEADERS), 1, fp);

	*oep = (app_pc)(imgNtHdr.OptionalHeader.ImageBase + imgNtHdr.OptionalHeader.AddressOfEntryPoint);

	fclose(fp);
	return TRUE;
}

void __cdecl print_disasm(void* drcontext, app_pc instr_addr, size_t instr_addr_fixed) {
	byte* pc;
	instr_t instr;
	instr_init(drcontext, &instr);
	instr_reset(drcontext, &instr);
	pc = decode(drcontext, instr_addr, &instr); // fill in instr

	size_t disasm_buf_size = 254;
	unsigned char* disasm_buf = (unsigned char*)dr_global_alloc(sizeof(unsigned char) * disasm_buf_size);
	instr_disassemble_to_buffer(dr_get_current_drcontext(), &instr, disasm_buf, disasm_buf_size);
	dr_printf("[DDR] [INFO] Disasm(PC 0x%x): %s\n", instr_addr_fixed, disasm_buf);
	dr_global_free(disasm_buf, sizeof(unsigned char) * disasm_buf_size);
	instr_free(drcontext, &instr);
}

unsigned long djb2_hash(unsigned char* str) {
	unsigned long hash = 5381;
	int c;

	while (c = *str++)
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

	return hash;
}

unsigned char* strtoupper(unsigned char* s) {
	char* t = s;
	while (*s) {
		*s = toupper(*s);
		s++;
	}
	return t;
}

void check_strlen(char* str, size_t maxlen, char* failmsg, unsigned int linenr) {
	if (strlen(str) > maxlen) {
		dr_printf("[DDR] [ERROR] %s. Max. length is %d for this field in Line %d.\n", failmsg, maxlen, linenr);
		usage();
		dr_exit_process(1);
	}
}

bool fix_comma_in_jsonfile(char *fname) {
// Checking for a wrong set comma at the end of the last block in the JSON file
	file_t f;
	bool ret = false;
	uint64 fsize = 0;
	char* buf;
	size_t buf_len;
	ssize_t i;
	bool c_bracket = false;
	bool s_bracket = false;
	bool next_c_bracket = false;

	dr_printf("[DDR] [INFO] Fixing file: %s\n", fname);

	f = dr_open_file(fname, DR_FILE_READ);
	if (f == INVALID_FILE) {
		dr_printf("[DDR] [ERROR] Can't open instruction log file for reading.\n");
		dr_printf("[DDR] [ERROR] Filename: '%s'\n", fname);
		dr_exit_process(1);
	}

	dr_file_size(f, &fsize);
	if (fsize > UINT_MAX) {
		dr_printf("[DDR] [WARNING] Can't cleanup JSON file. File is too big. Filesize is %.0lf\n", fsize);
	}
	else {
		buf_len = (size_t)fsize;
		buf = dr_global_alloc(sizeof(char) * buf_len);
		ssize_t n = dr_read_file(f, buf, buf_len);
		dr_close_file(f);
		
		for (i = n; i > n - 12; i--) {
			if (buf[i] == '}') {
				c_bracket = true;
			}
			if (buf[i] == ']' && c_bracket) {
				s_bracket = true;
			}
			if (buf[i] == ',' && s_bracket) {
				buf[i] = ' ';
				dr_printf("[DDR] [INFO] Fixed comma at the end of JSON file.\n");
				break;
			}
			if (buf[i] == '}' && s_bracket) {
				dr_printf("[DDR] [INFO] JSON file is ok, no comma at the end found.\n");
				break;
			}
		}
		dr_printf("[DDR] [INFO] Opening file: %s for writing\n", fname);
		f = dr_open_file(fname, DR_FILE_WRITE_OVERWRITE);
		if (f == INVALID_FILE) {
			dr_printf("[DDR] [ERROR] Can't open file for writing.\n");
			dr_printf("[DDR] [ERROR] Filename: '%s'\n", fname);
			dr_exit_process(1);
		}
		dr_printf("[DDR] [INFO] Writing fixed buffer to file: %s\n", fname);
		n = dr_write_file(f, buf, buf_len);
		if (buf_len != n) {
			dr_printf("[DDR] [WARNING] Org. JSON file (%d) and fixed JSON file (%d) have a different length. \n", buf_len, n);
		}
		else {
			ret = true;
		}

		dr_close_file(f);
		dr_printf("[DDR] [INFO] Done. Final logfile %s written. Length: %d bytes.\n", fname, n);

		dr_global_free(buf, sizeof(char) * buf_len);
	}

	return ret;
}

app_pc my_opnd_compute_address(opnd_t opnd, dr_mcontext_t* mc) {
// Wrapper to opnd_compute_address that verifies that opnd is a memory reference
	app_pc pc;

	if (opnd_is_memory_reference(opnd)) {
		pc = opnd_compute_address(opnd, mc);
	}
	else {
		pc = 0;
	}

	return pc;
}

bool my_opnd_is_reg(opnd_t opnd) {
// Wrapper to opnd_is_reg that verifies the operant is a register 

	reg_id_t reg = 0;
	void* drcontext;

	if (opnd_is_reg(opnd)) {
		if (reg = opnd_get_reg(opnd)) {
			drcontext = dr_get_current_drcontext();
			dr_mcontext_t mc = { sizeof(mc),DR_MC_ALL };
			dr_get_mcontext(drcontext, &mc);
			if (reg_is_xmm(reg)) {
#ifdef _DEBUG
				dr_printf("[DDR] [DEBUG] Operant is XMM Register this is not supported in the moment\n");
#endif
				return FALSE;
			}
		}
		return TRUE;
	}
	return FALSE;
}

int IncProcCounter() {
// Initalize or increase process counter and return number of running processes launched by the sample

	HANDLE hMapFile;
	int Counter;
	int* pCounter = &Counter;

	hMapFile = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,   // read/write access
		FALSE,                 // do not inherit the name
		szName);               // name of mapping object

	if (hMapFile == NULL) {
		debug_print("First instance.\n");

		Counter = 1;

		hMapFile = CreateFileMapping(
			INVALID_HANDLE_VALUE,    // use paging file
			NULL,                    // default security
			PAGE_READWRITE,          // read/write access
			0,                       // maximum object size (high-order DWORD)
			sizeof(unsigned int),    // maximum object size (low-order DWORD)
			szName);                 // name of mapping object

		if (hMapFile == NULL) {
			dr_printf("[DDR] [ERROR] [%s:%d] Could not create file mapping object (%d).\n", GetLastError(), __FILE__, __LINE__);
			return -1;
		}
		pCounter = (unsigned int*)MapViewOfFile(hMapFile,   // handle to map object
			FILE_MAP_ALL_ACCESS,							// read/write permission
			0,
			0,
			sizeof(unsigned int));

		if (pCounter == NULL) {
			dr_printf("[DDR] [ERROR] [%s:%d] Could not map view of file (%d).\n", GetLastError(), __FILE__, __LINE__);
			CloseHandle(hMapFile);
			return -1;
		}

		CopyMemory((PVOID)pCounter, &Counter, sizeof(unsigned int));

		debug_print("process counter = %u.\n", Counter);

		//UnmapViewOfFile(pBuf);  TBD: unmap file after last process.
		//CloseHandle(hMapFile);

		return Counter;
	}
	else {
		debug_print("Not the first process.\n");

		pCounter = (unsigned int*)MapViewOfFile(hMapFile,	
			FILE_MAP_ALL_ACCESS,							
			0,
			0,
			sizeof(unsigned int));

		if (pCounter == NULL) {
			dr_printf("[DDR] [ERROR] [%s:%d] Could not map view of file (%d).\n",GetLastError(), __FILE__, __LINE__);
			CloseHandle(hMapFile);
			return -1;
		}

		Counter = ++(*pCounter);
		debug_print("Increased process counter = %u.\n", Counter);

		return Counter;
	}
}

int DecProcCounter() {
// Decrease process counter and return number of running processes launched by the sample

	HANDLE hMapFile;
	int Counter;
	int* pCounter = &Counter;

	hMapFile = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,   
		FALSE,                 
		szName);               

	if (hMapFile == NULL) {
		dr_printf("[DDR] [ERROR] [%s:%d] Failed to open shared object.\n", __FILE__, __LINE__);
		return -1;
	}

	pCounter = (int*)MapViewOfFile(hMapFile, 
		FILE_MAP_ALL_ACCESS,  
		0,
		0,
		sizeof(unsigned int));

	if (pCounter == NULL) {
		dr_printf("[DDR] [ERROR] [%s:%d] Could not map view of file (%d).\n", GetLastError(), __FILE__, __LINE__);
		CloseHandle(hMapFile);
		return -1;
	}

	Counter = --(*pCounter);
	debug_print("Decreased process counter = %u.\n", Counter);

	return Counter;
}

int GetProcCounter() {
// Return number of launched processes by the sample

	HANDLE hMapFile;
	int Counter;
	int* pCounter = &Counter;

	hMapFile = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,   
		FALSE,                 
		szName);               

	if (hMapFile == NULL) {
		dr_printf("[DDR] [ERROR] [%s:%d] Failed to open shared object.\n", __FILE__, __LINE__);
		return -1;
	}

	pCounter = (int*)MapViewOfFile(hMapFile, 
		FILE_MAP_ALL_ACCESS,  
		0,
		0,
		sizeof(unsigned int));

	if (pCounter == NULL) {
		dr_printf("[DDR] [ERROR] [%s:%d] Could not map view of file (%d).\n", GetLastError(), __FILE__, __LINE__);
		CloseHandle(hMapFile);
		return -1;
	}

	Counter = *pCounter;
	debug_print("process counter = %u.\n", Counter);

	return Counter;
}

process_id_t* getSharedProcessIDs(process_id_t* pProcessids) {
// Return shared object pointing to Process IDs (pProcessids)

	HANDLE hMapFile;

	hMapFile = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,  
		FALSE,                
		szProcIDs);               

	if (hMapFile == NULL) {
		debug_print("Creating ProcessIDs shared memory.\n");

		hMapFile = CreateFileMapping(
			INVALID_HANDLE_VALUE,    
			NULL,                    
			PAGE_READWRITE,          
			0,                       
			MAX_PROCESSES * sizeof(process_id_t),   
			szProcIDs);							

		if (hMapFile == NULL) {
			dr_printf("[DDR] [ERROR] [%s:%d] Could not create file mapping object (%d).\n", GetLastError(), __FILE__, __LINE__);
			return NULL;
		}
		pProcessids = (process_id_t*)MapViewOfFile(hMapFile,   
			FILE_MAP_ALL_ACCESS,							   
			0,
			0,
			MAX_PROCESSES * sizeof(process_id_t));

		if (pProcessids == NULL) {
			dr_printf("[DDR] [ERROR] [%s:%d] Could not map view of file (%d).\n", GetLastError(), __FILE__, __LINE__);
			CloseHandle(hMapFile);
			return NULL;
		}
		return pProcessids;
	}
	else {
		debug_print("Not the first process.\n");

		pProcessids = (process_id_t*)MapViewOfFile(hMapFile,	
			FILE_MAP_ALL_ACCESS,							    
			0,
			0,
			MAX_PROCESSES * sizeof(process_id_t));

		if (pProcessids == NULL) {
			dr_printf("[DDR] [ERROR] [%s:%d] Could not map view of file (%d).\n", GetLastError(), __FILE__, __LINE__);
			CloseHandle(hMapFile);
			return NULL;
		}
		return pProcessids;
	}
}

char* getSharedProcessNames(char* pProcessnames) {
// Return shared object pointing to process names (pProcessnames)

	HANDLE hMapFile;

	hMapFile = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,   
		FALSE,                 
		szProcNames);          

	if (hMapFile == NULL) {
		debug_print("Creating ProcessNames shared memory.\n");

		hMapFile = CreateFileMapping(
			INVALID_HANDLE_VALUE,										
			NULL,														
			PAGE_READWRITE,												
			0,															
			MAX_PROCESSES * MAX_PROCESSNAME * sizeof(char),				
			szProcNames);												

		if (hMapFile == NULL) {
			dr_printf("[DDR] [ERROR] [%s:%d] Could not create file mapping object (%d).\n", GetLastError(), __FILE__, __LINE__);
			return NULL;
		}
		pProcessnames = (char*)MapViewOfFile(hMapFile,   
			FILE_MAP_ALL_ACCESS,						 
			0,
			0,
			MAX_PROCESSES * MAX_PROCESSNAME * sizeof(char));

		if (pProcessnames == NULL) {
			dr_printf("[DDR] [ERROR] [%s:%d] Could not map view of file (%d).\n", GetLastError(), __FILE__, __LINE__);
			CloseHandle(hMapFile);
			return NULL;
		}
		return pProcessnames;
	}
	else {
		debug_print("Not the first process.\n");

		pProcessnames = (char*)MapViewOfFile(hMapFile,	
			FILE_MAP_ALL_ACCESS,						
			0,
			0,
			MAX_PROCESSES * MAX_PROCESSNAME * sizeof(char));

		if (pProcessnames == NULL) {
			dr_printf("[DDR] [ERROR] [%s:%d] Could not map view of file (%d).\n", GetLastError(), __FILE__, __LINE__);
			CloseHandle(hMapFile);
			return NULL;
		}
		return pProcessnames;
	}
}

char* getSharedLogpath(char* pLogpath) {
// Return shared object pointing to plogpath
// pLogpath will be the path from the sample file
// pLogpath needs to be allocated by caller with min. MAX_PATH

	HANDLE hMapFile;

	hMapFile = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,   
		FALSE,                 
		szLogPath);            

	if (hMapFile == NULL) {
		debug_print("Creating Logpath shared memory object.\n");

		hMapFile = CreateFileMapping(
			INVALID_HANDLE_VALUE,							
			NULL,											
			PAGE_READWRITE,									
			0,												
			MAX_PATH,										
			szLogPath);										

		if (hMapFile == NULL) {
			dr_printf("[DDR] [ERROR] [%s:%d] Could not create file mapping object (%d).\n", GetLastError(), __FILE__, __LINE__);
			return NULL;
		}
		pLogpath = (char*)MapViewOfFile(hMapFile,   
			FILE_MAP_ALL_ACCESS,					
			0,
			0,
			MAX_PATH);

		if (pLogpath == NULL) {
			dr_printf("[DDR] [ERROR] [%s:%d] Could not map view of file (%d).\n", GetLastError(), __FILE__, __LINE__);
			CloseHandle(hMapFile);
			return NULL;
		}

		module_data_t *app = dr_get_main_module();
		if (getLogFilePath(app->full_path, pLogpath) == NULL) {
			dr_printf("[DDR] [ERROR] [%s:%d] Failed to extract global logpath from log filename\n.", __FILE__, __LINE__);
			dr_exit_process(1);
		}
		dr_free_module_data(app);
		debug_print("[FIRST PROC FIRST THREAD] Using log path %s\n", pLogpath);

		return pLogpath;
	}
	else {
		debug_print("Not the first process.\n");

		pLogpath = (char*)MapViewOfFile(hMapFile,	
			FILE_MAP_ALL_ACCESS,					
			0,
			0,
			MAX_PATH);

		if (pLogpath == NULL) {
			dr_printf("[DDR] [ERROR] [%s:%d] Could not map view of file (%d).\n", GetLastError(), __FILE__, __LINE__);

			CloseHandle(hMapFile);

			return NULL;
		}
		debug_print("[SUB THREAD] Using log path %s\n", pLogpath);
		return pLogpath;
	}
}

char* getLogFilePath(char* fullpath, char *dir) {
// return path from fullpath e.g. "C:\\abc\\test.txt" -> "C:\\abc\\" 
// char *dir needs to allocated by caller with min. MAX_PATH

	errno_t e;
	char driveletter[3];
	char dirpart[MAX_PATH];

	e = _splitpath_s(fullpath, driveletter, 3, dirpart, MAX_PATH, NULL, 0, NULL, 0);

	if (e == 0) {
		CopyMemory((PVOID)dir, driveletter, sizeof(driveletter));
		CopyMemory((PVOID)(dir+2), dirpart, MAX_PATH-2);
		return dir;
	}
	else {
		return NULL;
	}
}

