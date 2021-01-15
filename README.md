# rbx-script-analyzer
Analyze roblox exploiting scripts and reverse engineer them. Usefull if you are trying to analyze malicious obfuscated scripts.

Instructions:
1. Execute Script-Analyzer.lua in a roblox game (synapse only)
2. Execute scripts you want to analyze

Features:

All commands are followed by a second argument. The second argument is always a bool value (true or false).
- disablehttpreq - Blocks http requests. Usefull for analyzing malicious scripts without consequences.
- disablewebhook - Blocks all http requests that involve discord webhooks.
- http - Analyze http requests made by the script. This will also log syn.requests.
- remote - Logs all remotes that are invoked/fired by the script.
- namecall - Logs all namecalls that are invoked by the script.
- index - Logs all indexes that are invoked by the script.
- _gtable - Logs all changes made to the _G table.
- syntable - Logs all changes made to the syn table.

Example: http true/http false

![](./Images/1.PNG)
![](./Images/2.PNG)
![](./Images/3.PNG)
