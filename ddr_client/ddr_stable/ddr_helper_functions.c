#include "ddr.h"
#include "globals.h"

void usage()
{
	// -no_follow_children drrun does not follow into any child processes
	dr_printf("\n");
	dr_printf("Usage:\n");
	dr_printf("drrun.exe -c <DDR.DLL> -c <CFG_FILE> -- <SAMPLE.EXE>\n");
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
			size_t mlen = stmp2 - (stmp1 + slen);
			ret = dr_global_alloc(mlen + 1);
			if (ret != NULL)
			{
				memcpy(ret, stmp1 + slen, mlen);
				ret[mlen] = '\0';
				return ret;
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
	dr_global_free(disasm_buf, disasm_buf_size);
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
	}
	return ret;
}