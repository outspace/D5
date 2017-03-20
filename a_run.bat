ECHO OFF
ECHO BATCH test
FOR %%a IN (*.txt) DO (	
	heys.exe e 1 %%a "%%a.bin"
)