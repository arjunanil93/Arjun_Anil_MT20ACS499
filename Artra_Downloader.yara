rule search_artra
{
meta:
	author = "Arjun Anil"
	date = "2021-08-26"
	description = "To find malwares coming under Artra Downloader"

strings:
	$a = "TerminateProcess"
	$b = "WriteFile"
	$c = "GetCurrentThreadId"
	$d = "GetCurrentProcessId"
	$e = "ShellExecute"

condition:
	$a and $b and $c and $d and $e
}