# rpcls

This project was made to assist in a larger research project.

It pulls from a running process' PEB to enumerate the loaded DLLs. If a process imports
`RPCRT4.dll`, it then rips the PE from memory and searches the Import Address Table for functions
that indicate where the PE in question is acting as a client, server, or both.

If you use this, expect errors if you're not running as SYSTEM. Although this enables
`SePrivilegeDebug` for you, some processes still aren't accessible to you. They print to stderr, so
you canredirect output to a file. Each line is JSON, and contains the following fields:

```json
{
  "pid": <int>,
  "name": <string>,
  "path": <string>,
  "user": <string>,
  "role": <string>(SERVER|CLIENT|BOTH)
}
```
