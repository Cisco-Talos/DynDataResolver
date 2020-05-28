These are test sample to test DDR with if you don't want to use real malware.

NN = 32 bit or 64 bit

testsample0_NN_dyn.exe          - simple program doing a couple of calculations and function calls

testsample0_NN_debug_stat.exe   - same as above, but with debugging and statically compiled. This means it is filled with all the VS debug and lib
                                  functions, which makes it excute a lot of additional instructions, so it is good for testing the max. instructions 
                                  logging limit, the timeouts and check out the time it takes to process many instructions in IDA 

testsample1_NN.exe              - Launches a dialog box, three threads and a notepad.exe process

testsample2_NN.exe              - Copies itself to the %TEMP% folder and launces a 2nd instance of itself as EvIlMaLwArE.exe
                                  Also launches write.exe/wordpad.exe in the beginning and a notepad at the end

    


Caveats:
--------

1)

There is an issue with DynamoRIO in the moment. It doesn't support injection for 32bit processes which are launching
64bit child processes. A Scenario which some of the test samples above are doing e.g. testsample2_32.exe launches notepad.exe
which could be 64bit process depending on the OS you are running it on.
You can still analyse those processes with DDR, the only caveat is that DDR (or better the underlying DynmaoRIO) is not recognizing 
the 64bit processes in this scenario and thou will not trace any data for it. The initial 32bit process is still analysed.

If you run in such a scenario and want to verify it, you could run DynamoRio in debug mode e.g. :

C:\tools\DDR\DynamoRIO-Windows-8.0.0-1\bin32\drrun.exe -debug -checklevel 0 -loglevel 2 -- testsample32.exe

this will write a detailed logging file to C:\tools\DDR\DynamoRIO-Windows-8.0.0-1\logs\<name of process>\log.<some number>.html

You can find an entry like this one in it:

--- snip ---
syscall: NtCreateUserProcess presys \??\C:\windows\write.exe
Exit from system call
post syscall: sysnum=0x000000aa, params @0x0016f22c, result=0x00000000
syscall: NtCreateUserProcess => 0x0
syscall: NtCreateUserProcess created process 0x848 with main thread 0xd28
WARNING: make_writable 0x73dc6000: param size 0x3f000 vs. mbi size 0x2c000 base 0x73dc6000
WARNING: make_writable 0x73df2000: param size 0x13000 vs. mbi size 0x7000 base 0x73df2000
WARNING: make_unwritable 0x73dc6000: param size 0x3f000 vs. mbi size 0x2c000 base 0x73dc6000
WARNING: make_unwritable 0x73df2000: param size 0x13000 vs. mbi size 0x7000 base 0x73df2000
SYSLOG_WARNING: Injecting from 32-bit into 64-bit process is not yet supported.
syscall: NtCreateUserProcess: WARNING: failed to get cxt of thread (0xc000000d) so can't follow children on WOW64.
--- snip ---

Luckily for malware analysis, this scenario is not happening very often.

You can find more infos at https://blog.talosintelligence.com/ search for DDR or Dynamic
Data Resolver to find the latest blog about DDR.

2) Under certain rare contitions the client DLL is crashing if you have NOP'ed out instructions. This bug is under investigation. A
   dirty workaround is to clear the configuration in IDA (DDR/Config/Clear configured DDR request) and re-run the sample again. 

   