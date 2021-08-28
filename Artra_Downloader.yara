rule search_artra
{
meta:
	author = "Arjun Anil"
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
