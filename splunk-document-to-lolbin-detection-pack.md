# Splunk Detection Pack: Document / Download to Process to Living-off-the-Land

Version 1.0, written 2026-11-25. Built on Sysmon data. **Not yet run against your data.** Every field name and macro below is based on the standard Splunk Add-on for Sysmon / Windows TA layout, so run the sanity checks in section 2 before you trust any output. Expect one to two weeks of tuning before this is quiet enough to page on.

---

## 1. What this pack does

The goal is to answer, for any living-off-the-land (LOLBin) execution: **who clicked, what they opened, where it came from, which processes ran in between, and what the LOLBin did next.**

The chain it reconstructs:

```
Browser / Outlook / Teams writes file          Sysmon 15 (Zone.Identifier = came from the internet)
        |
User double-clicks it                           explorer.exe -> opener (Word, Excel, OneNote, PDF reader, wscript...)
        |
Opener spawns (maybe through cmd/powershell)    Sysmon 1, linked by ProcessGuid, up to 5 levels deep
        |
LOLBin runs with abusive arguments              certutil, mshta, regsvr32, rundll32, bitsadmin, wmic, msiexec ...
        |
LOLBin touches the network or drops files       Sysmon 3, 11, 22 (second-stage confirmation)
```

Searches in this pack:

| # | Name | Purpose | Run as |
|---|------|---------|--------|
| B1-B4 | Builder searches | Keep lineage, download and prevalence lookups fresh | Scheduled, every 5 min / daily |
| D1 | Document-to-LOLBin chain | Main detection with full ancestry, download link and risk score | Correlation search, every 5 min |
| D2 | LOLBin follow-on activity | Confirms D1 hits by network, file drops, DNS from the same process | Correlation search |
| D3 | LOLBin external network connection | Catches LOLBins talking to the internet even if D1 missed the parent chain | Correlation search |
| D4 | Document app drops executable content | Office/PDF apps writing scripts, DLLs, EXEs | Correlation search |
| H1 | No-admin standalone version of D1 | Uses `join` instead of KV store lookups, for analysts without admin rights | Ad hoc hunt |
| T1-T4 | Triage pivots | One-click follow-up searches for the analyst | Ad hoc |

Design choices worth knowing:

1. **Everything links on `ProcessGuid` / `ParentProcessGuid`**, never process name or PID (PIDs get reused).
2. **Binaries are identified by `OriginalFileName`**, not just file name, so a renamed `certutil.exe` is still caught (and scored higher for being renamed).
3. **Detections add to a risk score** instead of firing on a single string match. A bare `certutil.exe` scores low and never alerts. Word spawning a renamed `certutil.exe` with `-urlcache` on a file from the internet scores very high.
4. **Allowlisting and rarity are built in**, because without them any LOLBin detection drowns in SCCM, Intune and installer noise.

---

## 2. Prerequisites and sanity checks

### 2.1 Sysmon events needed

| Event | Used for | Required? |
|-------|----------|-----------|
| 1 Process Create | Everything. Needs `ProcessGuid`, `ParentProcessGuid`, `OriginalFileName`, `CommandLine`, `ParentImage`, `User` | Yes |
| 15 FileCreateStreamHash | Mark of the Web (Zone.Identifier): proves a file came from the internet, and which process wrote it | Yes for the download link |
| 3 Network Connect | D2, D3 | Strongly recommended |
| 11 File Create | D2, D4 | Strongly recommended |
| 22 DNS Query | D2 | Optional |
| 7 Image Load | Optional macro indicator (section 9.2) | Optional |

Use a current Sysmon version. `OriginalFileName` and DNS logging need Sysmon 10 or later.

### 2.2 Make sure Event 15 actually fires where users save files

Event 15 only fires for paths your Sysmon config watches. Make sure the config includes something like this (merge into your existing config, do not replace it):

```xml
<RuleGroup name="MOTW" groupRelation="or">
  <FileCreateStreamHash onmatch="include">
    <TargetFilename condition="contains">\Downloads\</TargetFilename>
    <TargetFilename condition="contains">\Desktop\</TargetFilename>
    <TargetFilename condition="contains">\Documents\</TargetFilename>
    <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
    <TargetFilename condition="contains">\Content.Outlook\</TargetFilename>
    <TargetFilename condition="contains">\INetCache\</TargetFilename>
  </FileCreateStreamHash>
</RuleGroup>
```

The SwiftOnSecurity and sysmon-modular configs cover most of this already, but check yours.

### 2.3 Sanity-check searches (run these first)

Do events 1, 3, 11, 15, 22 arrive?

```
`sysmon` earliest=-24h | stats count by EventCode | sort EventCode
```

Do the key fields extract on Event 1?

```
`sysmon` EventCode=1 earliest=-1h
| stats count as total count(ProcessGuid) as has_guid count(ParentProcessGuid) as has_parent_guid count(OriginalFileName) as has_orig count(CommandLine) as has_cmd count(ParentImage) as has_parent_image
```

Every number should be close to `total`. If `has_orig` is low, your Sysmon is too old or the field is named differently.

Does Event 15 carry the Zone.Identifier text?

```
`sysmon` EventCode=15 earliest=-24h
| stats count count(Contents) as has_contents
| appendcols [ search `sysmon` EventCode=15 earliest=-24h Contents="*ZoneId=3*" | stats count as zone3 ]
```

If `has_contents` is zero, the `Contents` field is not being extracted by your TA. Fix that before building D1's download link.

---

## 3. One-time setup

### 3.1 Macros

Create these in **Settings > Advanced search > Search macros**. Definitions must **not** start with a pipe. Where a name has arguments, enter them in the Arguments box.

**`sysmon`** (change index and sourcetype to match yours)

```
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

**`doc_apps_re`** (applications that open documents; used as a regex string)

```
"\\\\(winword|excel|powerpnt|onenote|outlook|msaccess|mspub|visio|acrord32|acrobat|foxitpdfreader|foxitreader|sumatrapdf|wordpad)\.exe$"
```

**`ancestor_filter`** (which process creations are worth keeping as ancestors; keeps the lineage store small)

```
match(lower(Image),"\\\\(winword|excel|powerpnt|onenote|outlook|msaccess|mspub|visio|acrord32|acrobat|foxitpdfreader|foxitreader|sumatrapdf|wordpad|explorer|cmd|powershell|pwsh|wscript|cscript|mshta|wmiprvse|wsmprovhost|psexesvc|winrshost|chrome|msedge|firefox|brave|thunderbird|teams|7zfm|winrar|certutil|regsvr32|rundll32|bitsadmin|wmic|msiexec|msbuild|installutil|regasm|regsvcs|cmstp|forfiles|pcalua|odbcconf|mavinject|curl|hh|schtasks)\.exe$") OR match(lower(Image),"\\\\(appdata|temp|downloads|desktop|documents|programdata)\\\\|\\\\users\\\\public\\\\")
```

The second `match` keeps anything running from a user-writable location, which is how dropped payloads sit in the middle of a chain.

**`lolbin_classify`** (the rule engine; sets `bin`, `renamed`, `base`, `mitre`, `technique`)

```
eval img=lower(Image), cmd=lower(CommandLine), parent_image=lower(ParentImage), orig=lower(coalesce(OriginalFileName,""))
| eval exe_name=replace(replace(img,"^.*\\\\",""),"\.exe$","")
| eval orig_name=replace(orig,"\.(exe|dll)$","")
| eval bin=if(orig_name!="" AND orig_name!="-",orig_name,exe_name)
| eval renamed=if(orig_name!="" AND orig_name!="-" AND orig_name!=exe_name,1,0)
| eval hit=case(
    bin="certutil" AND match(cmd,"[-/](urlcache|verifyctl|decode|decodehex|encode)"), "45|T1105;T1140;T1132|certutil download/decode/encode",
    bin="mshta" AND match(cmd,"https?://|javascript:|vbscript:|\.hta|about:|\.sct"), "60|T1218.005|mshta remote or inline script",
    bin="regsvr32" AND match(cmd,"[-/]i:|scrobj|https?://|\\\\\\\\[^\\\\]+\\\\"), "55|T1218.010|regsvr32 scriptlet or remote (Squiblydoo)",
    bin="rundll32" AND match(cmd,"comsvcs[^ ]*[ ,]+(#?24|minidump|full)"), "85|T1003.001|rundll32 comsvcs MiniDump (LSASS dump)",
    bin="rundll32" AND match(cmd,"javascript:|mshtml|https?://|advpack|ieadvpack|setupapi|url\.dll|zipfldr|pcwutl|shdocvw|ieframe"), "55|T1218.011|rundll32 proxy execution",
    bin="bitsadmin" AND match(cmd,"[-/](transfer|addfile|setnotifycmdline|create)"), "50|T1197;T1105|bitsadmin job or transfer",
    bin="wmic" AND match(cmd,"process\s+call\s+create|[-/]node:|\.xsl|[-/]format:\s*\"?https?"), "50|T1047;T1220|wmic execution, remote node or XSL",
    bin="msiexec" AND match(cmd,"https?://|\\\\\\\\[^\\\\]+\\\\|[-/][yz]\b"), "50|T1218.007|msiexec remote or UNC MSI, DLL register",
    match(bin,"^(wscript|cscript)$") AND match(cmd,"\.(js|jse|vbs|vbe|wsf|wsh)\b") AND match(cmd,"\\\\(users|programdata|temp|appdata|downloads|public)\\\\|https?://|\\\\\\\\"), "45|T1059.005;T1059.007|script host running user-path or remote script",
    bin="msbuild" AND match(cmd,"\.(xml|csproj|vbproj|proj|targets|tasks)\b") AND match(cmd,"\\\\(users|programdata|temp|appdata|downloads|public)\\\\|https?://"), "55|T1127.001|msbuild building user-path project",
    match(bin,"^(installutil|regasm|regsvcs)$") AND match(cmd,"[-/]u\b|/logfile=|\\\\(users|programdata|temp|appdata|downloads|public)\\\\"), "50|T1218.004;T1218.009|.NET proxy execution",
    bin="cmstp" AND match(cmd,"[-/](s|ni|au)\b"), "55|T1218.003|cmstp INF execution",
    bin="forfiles" AND match(cmd,"[-/]c\b"), "40|T1202|forfiles indirect command execution",
    bin="pcalua" AND match(cmd,"[-/]a\b"), "45|T1202|pcalua indirect execution",
    bin="odbcconf" AND match(cmd,"[-/]a\s*\{?\s*regsvr|[-/]f\s+\S+\.rsp"), "50|T1218.008|odbcconf DLL load",
    bin="mavinject" AND match(cmd,"/injectrunning"), "70|T1218.013;T1055.001|mavinject DLL injection",
    bin="ieexec" AND match(cmd,"https?://"), "55|T1218|ieexec remote execution",
    bin="hh" AND match(cmd,"https?://|\.chm"), "45|T1218.001|hh.exe CHM or URL",
    bin="control" AND match(cmd,"\.cpl") AND match(cmd,"\\\\(users|programdata|temp|appdata|downloads|public)\\\\"), "45|T1218.002|control.exe loading user-path CPL",
    bin="wuauclt" AND match(cmd,"updatedeploymentprovider|runhandlercomserver"), "55|T1218|wuauclt DLL proxy execution",
    bin="scriptrunner" AND match(cmd,"-appvscript"), "45|T1218|scriptrunner proxy execution",
    bin="infdefaultinstall" AND match(cmd,"\.inf"), "40|T1218|InfDefaultInstall",
    match(bin,"^(expand|extrac32|makecab|esentutl|replace)$") AND match(cmd,"https?://|\\\\\\\\[^\\\\]+\\\\|:[^\\\\ ]+\.(exe|dll|ps1)|[-/]y\s.*[-/]d|/vss"), "40|T1105;T1564.004;T1003.003|file copy, ADS or VSS LOLBin",
    bin="ftp" AND match(cmd,"[-/]s:"), "40|T1105|ftp script download",
    bin="curl" AND match(cmd,"https?://") AND match(cmd,"-o\b|--output|-O\b|--remote-name|-T\b|--upload-file"), "30|T1105|curl download or upload",
    match(bin,"^(powershell|pwsh)$") AND match(cmd,"[-/](e|ec|enc|encodedcommand)\s+[a-z0-9+/=]{20,}|frombase64string|downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|start-bitstransfer|amsiutils|reflection\.assembly|[-/]w(indowstyle)?\s+h(idden)?"), "35|T1059.001|PowerShell download, encoded or hidden",
    bin="schtasks" AND match(cmd,"[-/]create") AND match(cmd,"\\\\(users|programdata|temp|appdata|downloads|public)\\\\|https?://|[-/]s\s"), "30|T1053.005|schtasks create pointing at user path or remote",
    bin="reg" AND match(cmd,"\bsave\b.*\b(sam|security|system)\b"), "70|T1003.002|reg save credential hives",
    bin="vssadmin" AND match(cmd,"delete\s+shadows|resize\s+shadowstorage"), "80|T1490|vssadmin shadow copy tampering",
    bin="ntdsutil" AND match(cmd,"\bifm\b|create\s+full"), "80|T1003.003|ntdsutil IFM dump",
    renamed=1 AND match(orig_name,"^(certutil|mshta|regsvr32|rundll32|bitsadmin|wmic|msiexec|cscript|wscript|msbuild|installutil|regasm|regsvcs|cmstp|powershell|pwsh)$"), "60|T1036.003|System binary running under a different file name",
    match(parent_image,`doc_apps_re`) AND match(bin,"^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|msbuild|certutil|bitsadmin|wmic|msiexec|installutil|regasm|regsvcs|cmstp|forfiles|pcalua|odbcconf|mavinject|curl|hh|schtasks|bash|wsl)$"), "40|T1204.002;T1059|Document app spawned a shell or LOLBin"
  )
| eval base=tonumber(mvindex(split(hit,"|"),0)), mitre=mvindex(split(hit,"|"),1), technique=mvindex(split(hit,"|"),2)
```

Order matters: `case()` returns the first match, so specific rules come first and the generic "document app spawned a shell" rule is the safety net at the end.

**`cmd_sig`** (a normalised command-line fingerprint for rarity scoring; strips user names, GUIDs and numbers)

```
eval cmd_norm=replace(replace(replace(cmd,"\\\\users\\\\[^\\\\]+","\\\\users\\\\u"),"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}","guid"),"\d+","n")
| eval cmd_sig=md5(bin."|".cmd_norm)
```

**`lineage_hop(2)`**, arguments `prev,n` (looks up one more ancestor from the KV store)

```
lookup process_lineage ProcessGuid AS p$prev$_pguid OUTPUT Image AS p$n$_img, CommandLine AS p$n$_cmd, ParentProcessGuid AS p$n$_pguid, User AS p$n$_user
```

**`lineage_join(2)`**, arguments `prev,n` (no-admin alternative to `lineage_hop`, used by H1)

```
join type=left max=1 p$prev$_pguid [ search `sysmon` EventCode=1 earliest=-7d@d | where `ancestor_filter` | rename ProcessGuid AS p$prev$_pguid, Image AS p$n$_img, CommandLine AS p$n$_cmd, ParentProcessGuid AS p$n$_pguid, User AS p$n$_user | fields p$prev$_pguid p$n$_img p$n$_cmd p$n$_pguid p$n$_user ]
```

**`opener_classify`** (finds the document app in the ancestry and extracts the document path from the command lines)

```
eval l1=lower(p1_img), l2=lower(p2_img), l3=lower(p3_img), l4=lower(p4_img), l5=lower(p5_img)
| eval opener_lvl=case(match(l1,`doc_apps_re`),1, match(l2,`doc_apps_re`),2, match(l3,`doc_apps_re`),3, match(l4,`doc_apps_re`),4, match(l5,`doc_apps_re`),5, true(),0)
| eval opener_img=case(opener_lvl=1,p1_img, opener_lvl=2,p2_img, opener_lvl=3,p3_img, opener_lvl=4,p4_img, opener_lvl=5,p5_img)
| eval opener_cmd=case(opener_lvl=1,p1_cmd, opener_lvl=2,p2_cmd, opener_lvl=3,p3_cmd, opener_lvl=4,p4_cmd, opener_lvl=5,p5_cmd)
| eval opener_user=case(opener_lvl=1,p1_user, opener_lvl=2,p2_user, opener_lvl=3,p3_user, opener_lvl=4,p4_user, opener_lvl=5,p5_user)
| eval opener_launcher=case(opener_lvl=1,p2_img, opener_lvl=2,p3_img, opener_lvl=3,p4_img, opener_lvl=4,p5_img)
| eval search_blob=coalesce(opener_cmd,"")." ".coalesce(CommandLine,"")." ".coalesce(p1_cmd,"")
| rex field=search_blob max_match=1 "(?i)\"(?<doc_q>(?:[a-z]:\\\\|\\\\\\\\)[^\"]+?\.(?:docm?|dotm?|docx|xlsm?|xlsb|xlsx|xlam|xll|pptm?|pptx|ppam|ppsm|one|pdf|rtf|lnk|iso|img|vhdx?|chm|hta|jse?|vbs|vbe|wsf|wsh|zip|rar|7z|html?|msi|xsl|sct|inf|cpl))\""
| rex field=search_blob max_match=1 "(?i)(?<doc_u>(?:[a-z]:\\\\|\\\\\\\\)[^\s\"]+?\.(?:docm?|dotm?|docx|xlsm?|xlsb|xlsx|xlam|xll|pptm?|pptx|ppam|ppsm|one|pdf|rtf|lnk|iso|img|vhdx?|chm|hta|jse?|vbs|vbe|wsf|wsh|zip|rar|7z|html?|msi|xsl|sct|inf|cpl))(?=\s|\"|$)"
| eval doc=coalesce(doc_q,doc_u)
```

**`dl_enrich`** (links the document to the download record: who wrote it, from where, and whether it carried the internet zone mark)

```
eval doc_lc=lower(doc), doc_name=lower(replace(doc,"^.*\\\\",""))
| lookup dl_files host path_lc AS doc_lc OUTPUT dl_time, dl_by, zone_id, referrer_url, host_url
| eval dl_match=if(isnotnull(dl_time),"exact path",null())
| lookup dl_files host name_lc AS doc_name OUTPUTNEW dl_time, dl_by, zone_id, referrer_url, host_url
| eval dl_match=coalesce(dl_match,if(isnotnull(dl_time),"filename only",null()))
```

`filename only` is a weaker link (the file was probably extracted from a zip or moved), so treat it as a lead, not proof.

**`risk_score`**

```
eval risk=base
| eval risk=risk+case(opener_lvl=1,40, opener_lvl>=2,30, true(),0)
| eval risk=risk+if(zone_id="3",20,0)
| eval risk=risk+if(renamed=1,25,0)
| eval risk=risk+if(match(cmd,"https?://|\\\\\\\\[^\\\\]+\\\\"),10,0)
| eval risk=risk+if(match(cmd,"\\\\(users|programdata|temp|appdata|downloads|public)\\\\"),10,0)
| eval risk=risk+if(len(CommandLine)>400 OR match(cmd,"[a-z0-9+/]{100,}={0,2}") OR match(cmd,"\^.*\^.*\^"),10,0)
| eval lineage_blob=lower(coalesce(p1_img,"")." ".coalesce(p2_img,"")." ".coalesce(p3_img,"")." ".coalesce(p4_img,"")." ".coalesce(p5_img,""))
| eval risk=risk+if(match(lineage_blob,"wmiprvse|wsmprovhost|psexesvc|winrshost"),15,0)
| eval risk=risk+if(isnotnull(dl_time) AND (_time-dl_time)<3600,5,0)
| eval host_count=coalesce(host_count,0)
| eval risk=risk+if(host_count<=2,10,0)-if(host_count>=100,10,0)
```

Scoring summary: base score from the rule (30 to 85), plus 40 if the document app spawned it directly (30 if there are shells in between), plus 20 if the document carried the internet zone mark, plus 25 if the binary was renamed, plus smaller bonuses for URLs/UNC paths, user-writable paths, obfuscation, remote-execution parents, fast detonation after download, and rarity. Alert threshold is 60.

**`chain_output`**

```
eval chain=coalesce(replace(p5_img,"^.*\\\\","")." > ","").coalesce(replace(p4_img,"^.*\\\\","")." > ","").coalesce(replace(p3_img,"^.*\\\\","")." > ","").coalesce(replace(p2_img,"^.*\\\\","")." > ","").coalesce(replace(p1_img,"^.*\\\\","")." > ","").replace(Image,"^.*\\\\","")
| eval process_tree=mvappend(
    if(isnotnull(p5_img),"5 up: ".p5_img." | ".substr(p5_cmd,1,200),null()),
    if(isnotnull(p4_img),"4 up: ".p4_img." | ".substr(p4_cmd,1,200),null()),
    if(isnotnull(p3_img),"3 up: ".p3_img." | ".substr(p3_cmd,1,200),null()),
    if(isnotnull(p2_img),"2 up: ".p2_img." | ".substr(p2_cmd,1,200),null()),
    if(isnotnull(p1_img),"1 up: ".p1_img." | ".substr(p1_cmd,1,200),null()),
    "this: ".Image." | ".substr(CommandLine,1,300))
| eval how_opened=case(isnull(opener_img),null(), match(lower(opener_launcher),"explorer\.exe$"),"double-clicked in Explorer", match(lower(opener_launcher),"outlook\.exe$"),"opened from Outlook", match(lower(opener_launcher),"(chrome|msedge|firefox|brave)\.exe$"),"opened from browser", isnotnull(opener_launcher),"launched by ".replace(opener_launcher,"^.*\\\\",""), true(),"launcher unknown")
| eval minutes_dl_to_exec=if(isnotnull(dl_time),round((_time-dl_time)/60,1),null())
| eval user=coalesce(opener_user,User)
| eval severity=case(risk>=100,"critical", risk>=80,"high", true(),"medium")
| table _time host user severity risk technique mitre chain how_opened doc dl_match dl_by zone_id referrer_url host_url minutes_dl_to_exec renamed host_count CommandLine process_tree ProcessGuid
| sort - risk
```

If your Splunk version does not support `mvappend` with null arguments the way described, wrap each `if(...)` in `coalesce(...,"")` and drop empty values with `mvfilter`.

### 3.2 KV store collections (needs an admin; skip to H1 if you cannot do this)

`collections.conf`

```
[process_lineage]
field.ProcessGuid = string
field.ParentProcessGuid = string
field.Image = string
field.CommandLine = string
field.User = string
field.host = string
field.seen = number
accelerated_fields.by_guid = {"ProcessGuid": 1}

[dl_files]
field.k = string
field.host = string
field.path_lc = string
field.name_lc = string
field.dl_time = number
field.dl_by = string
field.zone_id = string
field.referrer_url = string
field.host_url = string
accelerated_fields.by_path = {"host": 1, "path_lc": 1}
accelerated_fields.by_name = {"host": 1, "name_lc": 1}
```

`transforms.conf`

```
[process_lineage]
external_type = kvstore
collection = process_lineage
fields_list = _key, ProcessGuid, ParentProcessGuid, Image, CommandLine, User, host, seen

[dl_files]
external_type = kvstore
collection = dl_files
fields_list = _key, k, host, path_lc, name_lc, dl_time, dl_by, zone_id, referrer_url, host_url

[lolbin_allowlist]
filename = lolbin_allowlist.csv
match_type = WILDCARD(host), WILDCARD(parent_image), WILDCARD(cmdline)
case_sensitive_match = false
max_matches = 1

[lolbin_prevalence]
filename = lolbin_prevalence.csv
```

Check `limits.conf`, stanza `[kvstore]`, setting `max_rows_per_query` (default 50000). The `ancestor_filter` keeps the lineage store small enough that the daily prune in B4 stays under this limit on most fleets. If your fleet is large, check the row count of `| inputlookup process_lineage | stats count` after a day.

### 3.3 Allowlist file

Create `lolbin_allowlist.csv` (lookup file, all values lowercase, `*` as wildcard, every column filled in):

```
host,bin,parent_image,cmdline,allow_reason
*,msiexec,*\ccmexec.exe,*,EXAMPLE ONLY - SCCM software deployment (verify path in your environment)
*,powershell,*\agentexecutor.exe,*,EXAMPLE ONLY - Intune management extension (verify path)
*,certutil,*\tanium*,*,EXAMPLE ONLY - Tanium client (verify path)
```

The three rows above are placeholders. Build your real list from the tuning workflow in section 12 and always allowlist on parent path **and** a command-line pattern, never on binary name alone. Add `owner` and `reviewed` columns for your own housekeeping if you like; extra columns are ignored.

---

## 4. Builder searches (keep these running)

### B1. Process lineage builder

Schedule: every 5 minutes. Time range: earliest `-12m@m`, latest `now`.

```
`sysmon` EventCode=1
| where `ancestor_filter`
| eval seen=_time
| table ProcessGuid ParentProcessGuid Image CommandLine User host seen
| outputlookup append=t key_field=ProcessGuid process_lineage
```

The overlapping window is intentional; writes are idempotent because `ProcessGuid` is the key.

### B2. Download record builder

Schedule: every 5 minutes. Time range: earliest `-12m@m`, latest `now`.

```
`sysmon` EventCode=15
| rex field=TargetFilename "^(?<path>.+?):(?<stream>[^:\\\\]+)$"
| where lower(stream)="zone.identifier"
| rex field=Contents "(?i)ZoneId=(?<zone_id>\d)"
| rex field=Contents "(?i)ReferrerUrl=(?<referrer_url>\S+)"
| rex field=Contents "(?i)HostUrl=(?<host_url>\S+)"
| eval path_lc=lower(path), name_lc=lower(replace(path,"^.*\\\\","")), dl_by=Image, dl_time=_time
| eval k=md5(host."|".path_lc)
| table k host path_lc name_lc dl_time dl_by zone_id referrer_url host_url
| outputlookup append=t key_field=k dl_files
```

Note the `rex` that strips `:Zone.Identifier`. Event 15 reports the alternate data stream name as part of `TargetFilename`, so without this step the file path would never match the path in the opener's command line.

### B3. Command-line prevalence builder

Schedule: daily. Time range: earliest `-30d@d`, latest `@d`.

```
`sysmon` EventCode=1
| `lolbin_classify`
| where isnotnull(technique)
| `cmd_sig`
| stats dc(host) as host_count count as exec_count by cmd_sig
| outputlookup lolbin_prevalence.csv
```

### B4. Prune old lineage and download records

Schedule: daily at a quiet hour. Run each as its own saved search.

```
| inputlookup process_lineage
| where seen > relative_time(now(),"-3d@d")
| outputlookup key_field=ProcessGuid process_lineage
```

```
| inputlookup dl_files
| where dl_time > relative_time(now(),"-30d@d")
| outputlookup key_field=k dl_files
```

Do not run B4 at the same moment as B1/B2.

---

## 5. D1: Document / download to LOLBin chain (main detection)

Schedule: every 5 minutes (`*/5 * * * *`). Time range: earliest `-10m@m`, latest `-5m@m`. The 5-minute lag lets B1 and B2 catch up so parent processes are already in the lookup when the LOLBin is evaluated. If your forwarders lag more than that, widen the lag.

```
`sysmon` EventCode=1
| `lolbin_classify`
| where isnotnull(technique)
| lookup lolbin_allowlist host bin parent_image cmdline AS cmd OUTPUT allow_reason
| where isnull(allow_reason)
| eval p0_pguid=ParentProcessGuid
| `lineage_hop(0,1)`
| `lineage_hop(1,2)`
| `lineage_hop(2,3)`
| `lineage_hop(3,4)`
| `lineage_hop(4,5)`
| `opener_classify`
| `dl_enrich`
| `cmd_sig`
| lookup lolbin_prevalence cmd_sig OUTPUT host_count
| `risk_score`
| where risk>=60
| `chain_output`
```

### What the output columns mean

| Column | Meaning |
|--------|---------|
| `user` | The account that ran the document app. This is "who clicked". |
| `chain` | The full process tree, for example `explorer.exe > winword.exe > cmd.exe > certutil.exe` |
| `how_opened` | Whether the document was double-clicked in Explorer, opened from Outlook, or from a browser |
| `doc` | The document or script path pulled from the opener's command line |
| `dl_by`, `referrer_url`, `host_url`, `zone_id` | Which process wrote the file to disk, where it came from, and whether it had the internet zone mark (`3`) |
| `dl_match` | `exact path` is strong; `filename only` is a weaker lead |
| `minutes_dl_to_exec` | Time between download and execution. Very short is typical of phishing |
| `renamed` | `1` if the executable's file name differs from its internal original name |
| `host_count` | How many hosts ran this same command line in the last 30 days. Low is suspicious |
| `process_tree` | Each ancestor's image and command line, for the analyst |
| `ProcessGuid` | Use this for the T1 pivot |

### Severity

| Risk | Severity | Suggested action |
|------|----------|------------------|
| 60-79 | medium | Queue for review, add to risk-based alerting |
| 80-99 | high | Analyst review within the hour |
| 100+ | critical | Page |

---

## 6. D2: LOLBin follow-on activity (confirmation)

This takes the LOLBin executions D1 would consider and checks whether the same process then reached out, dropped a file, or resolved a domain. It works by `ProcessGuid`, so it also covers renamed binaries.

Schedule: every 5 minutes. Time range: earliest `-30m@m`, latest `now`.

```
`sysmon` (EventCode=3 OR EventCode=11 OR EventCode=22)
    [ search `sysmon` EventCode=1
      | `lolbin_classify`
      | where isnotnull(technique) AND base>=40
      | fields ProcessGuid ]
| eval ip_private=if(EventCode=3 AND (cidrmatch("10.0.0.0/8",DestinationIp) OR cidrmatch("172.16.0.0/12",DestinationIp) OR cidrmatch("192.168.0.0/16",DestinationIp) OR cidrmatch("127.0.0.0/8",DestinationIp) OR cidrmatch("169.254.0.0/16",DestinationIp) OR match(DestinationIp,"^(::1|fe80:|f[cd][0-9a-f]{2}:)")),1,0)
| where NOT (EventCode=3 AND ip_private=1)
| eval dropped_ext=if(EventCode=11 AND match(lower(TargetFilename),"\.(exe|dll|scr|ps1|bat|cmd|vbs|vbe|js|jse|hta|wsf|msi|lnk|sct|xsl|dat)$"),1,0)
| where EventCode!=11 OR dropped_ext=1
| eval activity=case(EventCode=3,"connect ".DestinationIp.":".DestinationPort." ".coalesce(DestinationHostname,""), EventCode=11,"wrote ".TargetFilename, EventCode=22,"dns ".QueryName)
| stats min(_time) as first_seen values(Image) as image values(User) as user values(activity) as activity
        max(eval(if(EventCode=3,1,0))) as net max(eval(if(EventCode=11,1,0))) as filedrop max(eval(if(EventCode=22,1,0))) as dns
        by host ProcessGuid
| eval risk=40*net+30*filedrop+10*dns
| where risk>=30
| eval first_seen=strftime(first_seen,"%F %T")
| table first_seen host user image risk activity ProcessGuid
| sort - risk
```

In a risk-based setup, run D1 and D2 as separate searches that both write risk to the same host. When both fire, the host's cumulative risk jumps, which is exactly the "suspicious command that then did something" signal.

The subsearch returns at most about 10,000 GUIDs and has a runtime cap. On large fleets keep the D2 window short.

---

## 7. D3: LOLBin making an external network connection

A standalone, high-fidelity rule. These binaries almost never need to talk to the internet on their own. It does not depend on the parent chain, so it catches cases where D1's ancestry is broken (parent PID spoofing, short-lived parents, lineage store gaps).

Schedule: every 10 minutes. Time range: earliest `-15m@m`, latest `-5m@m`.

```
`sysmon` EventCode=3 Initiated=true
| eval bin=replace(replace(lower(Image),"^.*\\\\",""),"\.exe$","")
| where match(bin,"^(certutil|mshta|regsvr32|rundll32|wmic|msiexec|cscript|wscript|installutil|regasm|regsvcs|msbuild|cmstp|hh|odbcconf|ieexec|presentationhost|forfiles|pcalua|expand|extrac32|esentutl|replace|infdefaultinstall|mavinject|ftp|scriptrunner)$")
| where NOT (cidrmatch("10.0.0.0/8",DestinationIp) OR cidrmatch("172.16.0.0/12",DestinationIp) OR cidrmatch("192.168.0.0/16",DestinationIp) OR cidrmatch("127.0.0.0/8",DestinationIp) OR cidrmatch("169.254.0.0/16",DestinationIp) OR match(DestinationIp,"^(::1|fe80:|f[cd][0-9a-f]{2}:)"))
| join type=left max=1 ProcessGuid
    [ search `sysmon` EventCode=1 | fields ProcessGuid CommandLine ParentImage ParentCommandLine ]
| eval risk=60+if(isnotnull(ParentImage) AND match(lower(ParentImage),`doc_apps_re`),40,0)
| table _time host User bin DestinationIp DestinationHostname DestinationPort CommandLine ParentImage risk ProcessGuid
| sort - risk
```

Expect false positives from `msiexec` (installers fetching from vendor CDNs) and occasionally `rundll32`. Allowlist by destination domain and parent after reviewing the first week. Confirm that your Sysmon config actually logs network connections for these images; many configs include them by image name, but renamed binaries will not be covered here (D2 handles those).

---

## 8. D4: Document apps writing executable content

Office and PDF apps should not be creating scripts, DLLs or executables. This catches the dropper stage even when the LOLBin that follows is something you do not list.

Schedule: every 10 minutes. Time range: earliest `-15m@m`, latest `-5m@m`.

```
`sysmon` EventCode=11
| eval img=lower(Image), tf=lower(TargetFilename)
| where match(img,`doc_apps_re`)
| where match(tf,"\.(exe|dll|scr|ps1|bat|cmd|vbs|vbe|js|jse|hta|wsf|msi|sct|xsl|jar|cpl)$")
        OR (match(tf,"\.lnk$") AND NOT match(tf,"\\\\microsoft\\\\windows\\\\recent\\\\"))
| eval risk=60+if(match(tf,"\\\\(users|programdata|temp|appdata|downloads|public)\\\\"),20,0)
| table _time host User Image TargetFilename risk ProcessGuid
| sort - risk
```

Tune out known add-in behaviour (some Office add-ins and updaters legitimately write DLLs under `AppData`).

---

## 9. Optional supporting hunts

### 9.1 Documents from the internet that were opened (no LOLBin required)

Useful for hunting delivery campaigns even before anything malicious runs:

```
`sysmon` EventCode=1
| eval l=lower(Image)
| where match(l,`doc_apps_re`)
| rex field=CommandLine max_match=1 "(?i)\"(?<doc>(?:[a-z]:\\\\|\\\\\\\\)[^\"]+?\.(?:docm?|xlsm?|xlsb|pptm?|one|pdf|rtf|iso|img|lnk|chm|hta|js|vbs|wsf|zip))\""
| where isnotnull(doc)
| eval doc_lc=lower(doc), doc_name=lower(replace(doc,"^.*\\\\",""))
| lookup dl_files host path_lc AS doc_lc OUTPUT dl_time, dl_by, zone_id, referrer_url, host_url
| where zone_id="3"
| table _time host User Image doc dl_by referrer_url host_url
```

### 9.2 Macro execution indicator (only if you log Event 7 for these DLLs)

```
`sysmon` EventCode=7
| where match(lower(Image),"\\\\(winword|excel|powerpnt)\.exe$") AND match(lower(ImageLoaded),"\\\\vbe7(intl)?\.dll$")
| table _time host User Image ImageLoaded ProcessGuid
```

Loading `vbe7.dll` means VBA was actually initialised in that Office process, which narrows "document opened" to "macro-capable content ran".

---

## 10. H1: No-admin standalone version of D1

If you cannot create KV store collections, run this ad hoc. It resolves the ancestors with `join` instead of the lineage lookup, and skips the download link (which needs B2). It is slower and subject to the `join` limits (50,000 subsearch rows, 60 seconds), so keep the time range short (a few hours) and add a `host=` filter when you can.

```
`sysmon` EventCode=1
| `lolbin_classify`
| where isnotnull(technique)
| eval p0_pguid=ParentProcessGuid
| `lineage_join(0,1)`
| `lineage_join(1,2)`
| `lineage_join(2,3)`
| `lineage_join(3,4)`
| `lineage_join(4,5)`
| `opener_classify`
| eval host_count=0
| `risk_score`
| where risk>=60
| `chain_output`
```

Because the download link is missing, `dl_match`, `zone_id` and related columns will be empty and the score will be up to 20 points lower than D1 would give. Run the T3 pivot below to check the download manually.

If you cannot create macros either, you can paste each macro's definition inline in place of its backtick name.

---

## 11. Triage pivots

### T1. Everything one process (and its direct children) did

Take `ProcessGuid` from a D1/D2/D3 result and substitute it:

```
`sysmon` (ProcessGuid="{GUID}" OR ParentProcessGuid="{GUID}")
| eval detail=coalesce(CommandLine,TargetFilename,DestinationIp.":".DestinationPort,QueryName,ImageLoaded,TargetImage)
| table _time EventCode host User ParentImage Image detail
| sort _time
```

### T2. Everything on the host around the alert

```
`sysmon` host="HOSTNAME" earliest="MM/DD/YYYY:HH:MM:SS" latest="MM/DD/YYYY:HH:MM:SS"
| eval detail=coalesce(CommandLine,TargetFilename,DestinationIp.":".DestinationPort,QueryName,ImageLoaded)
| table _time EventCode ProcessGuid Image detail
| sort _time
```

Use a window of roughly 15 minutes either side of the alert.

### T3. Where did the file come from, and who else received it?

By file name (substitute the name from `doc`):

```
`sysmon` EventCode=15 TargetFilename="*invoice*.docm*" earliest=-30d
| rex field=Contents "(?i)ReferrerUrl=(?<referrer_url>\S+)"
| rex field=Contents "(?i)HostUrl=(?<host_url>\S+)"
| stats min(_time) as first values(Image) as written_by values(referrer_url) as referrer values(host_url) as host_url by host TargetFilename
```

By source domain (find every host that downloaded from the same place):

```
`sysmon` EventCode=15 Contents="*suspicious-domain.example*" earliest=-30d
| stats count min(_time) as first values(TargetFilename) as files by host Image
```

### T4. Has this same command line run anywhere else?

```
`sysmon` EventCode=1 CommandLine="*distinctive-fragment*" earliest=-30d
| stats count dc(host) as hosts values(host) as host_list min(_time) as first max(_time) as last by ParentImage
```

### Analyst checklist (what to check first)

1. Who is the user and is the host a workstation or a server?
2. Read `chain`. Does a document app sit above a shell or LOLBin? Is there a process from a temp or download folder in the middle?
3. Read `referrer_url` / `host_url`. Is this a known business site, a file-sharing service, or a newly seen domain?
4. Read the LOLBin command line. What URL, UNC path, script or DLL was it pointed at?
5. Run T1. Did the LOLBin make a connection or drop files? Did the dropped file run (look for new Event 1 with a matching image path)?
6. Run T3 and T4 to scope: who else got the same file, and who else ran the same command?
7. If confirmed: isolate the host, collect the document and dropped files, block the URL/domain, reset the user's credentials.

---

## 12. Tuning workflow (do this before enabling alerting)

**Week 1: run in report mode.** Lower the D1 threshold to 40 and review the volume. Find what is noisy:

```
(run D1 with "| where risk>=40" and without chain_output)
| stats count dc(host) as hosts by bin parent_image
| sort - count
```

Anything that shows up on hundreds of hosts with the same parent is almost certainly management tooling. Add a narrow allowlist row for it (parent path plus command-line pattern). Never use `*` for both parent and command line.

**Week 2: raise the threshold to 60 and enable alerting.** Review every alert. For each false positive, ask whether the fix is an allowlist row, a rule change, or a score adjustment, and record the decision.

**Ongoing:**

1. Review the allowlist quarterly; remove rows for tools you have retired.
2. Re-run B3 weekly or daily so rarity stays current.
3. After any Sysmon config change, re-run the section 2.3 sanity checks.
4. Replay each Atomic test (section 14) after any rule change to prove nothing regressed.

---

## 13. Splunk Enterprise Security / risk-based alerting setup

Create D1 as a **correlation search** with these settings:

| Setting | Value |
|---------|-------|
| Cron | `*/5 * * * *` |
| Time range | Earliest `-10m@m`, latest `-5m@m` |
| Throttling | Window 1 hour, fields `host`, `technique`, `doc` |
| Risk adaptive response | Risk object `host`, type `system`, score = the `risk` field |
| Notable adaptive response | Only when `risk>=80` |
| MITRE annotations | `T1204.002`, `T1218`, `T1105`, `T1059`, `T1197`, `T1127.001`, `T1036.003` |

If you set the annotation via configuration instead of the UI:

```
action.correlationsearch.annotations = {"mitre_attack":["T1204.002","T1218","T1105","T1059","T1197","T1127.001","T1036.003"]}
```

Add these lines at the end of D1 for the risk action:

```
| eval risk_object=host, risk_object_type="system", risk_score=risk
| eval risk_message="Document-to-LOLBin chain on ".host.": ".chain." (".technique.")"
```

Without ES, use a standard scheduled alert with suppression: `alert.suppress = 1`, `alert.suppress.period = 1h`, `alert.suppress.fields = host,technique`.

Naming suggestion: `Endpoint - Document Download to LOLBin Execution Chain - Rule`.

---

## 14. Testing (lab machines only)

Never run any of this on production endpoints.

**Renamed-binary test (proves the `OriginalFileName` logic):**

```
copy %SystemRoot%\System32\certutil.exe %TEMP%\svc_helper.exe
%TEMP%\svc_helper.exe -urlcache -f http://<your-lab-web-server>/test.txt %TEMP%\test.txt
```

Expected: D1 returns `bin=certutil`, `renamed=1`.

**Document-chain test:**

1. Build a test document in the lab with a macro that runs `cmd.exe /c certutil.exe -urlcache -f http://<lab-server>/test.txt %TEMP%\t.txt`.
2. Download it with a browser from the lab web server and confirm Event 15 shows `ZoneId=3` for it (if the lab server is in your Local Intranet zone you may see a different zone or none, so check).
3. Double-click it from Downloads.

Expected: `chain` shows the browser-downloaded file leading to `explorer.exe > winword.exe > cmd.exe > certutil.exe`, `how_opened` says double-clicked in Explorer, `zone_id=3`.

Important: since mid-2022 Office blocks VBA macros in files that carry the internet zone mark by default. If macros are blocked in your lab, test the two halves separately: (a) the download link by checking section 9.1 returns the opened file, and (b) the macro-to-LOLBin chain on a copy with the mark removed (`Unblock-File` in PowerShell).

**Atomic Red Team:** use the Invoke-AtomicRedTeam framework against a lab machine. List what exists first (`Invoke-AtomicTest <ID> -ShowDetailsBrief`), then run and clean up (`-Cleanup`). Useful technique IDs for this pack: T1105, T1218.005, T1218.010, T1218.011, T1218.007, T1218.003, T1197, T1127.001, T1047, T1220, T1204.002, T1036.003.

For every test, confirm in order: Sysmon logged it, B1/B2 stored it, D1/D2/D3 fired, risk landed in the expected band.

---

## 15. If you do not have Sysmon

| Sysmon field | Windows Security 4688 | CIM `Endpoint.Processes` |
|--------------|-----------------------|--------------------------|
| `Image` | `NewProcessName` | `process_path` / `process_name` |
| `ParentImage` | `ParentProcessName` | `parent_process_path` / `parent_process_name` |
| `CommandLine` | `Process_Command_Line` (requires the "include command line" policy) | `process` |
| `ProcessGuid` | No equivalent (only `NewProcessId`, which is reused) | `process_guid` |
| `ParentProcessGuid` | No equivalent | `parent_process_guid` |
| `OriginalFileName` | No equivalent | `original_file_name` (if populated by your source) |
| Events 3, 11, 15, 22 | No direct equivalent | Network, Filesystem, Web data models, source-dependent |

With 4688 you lose reliable chain linking, renamed-binary detection and the download link, so treat results as lower fidelity. If you have an EDR feeding the CIM `Endpoint` model with GUIDs, adapt the field names and the same logic works.

---

## 16. Known gaps and evasions

| Gap | Why it matters | Mitigation |
|-----|----------------|------------|
| Shortcut (`.lnk`) launches | Explorer launches the shortcut target, and Sysmon does not record which `.lnk` caused it, so the chain starts at a shell with no document | D4 for Office-dropped LNKs; hunt `.lnk` files with internet zone mark from Event 15 on the same host just before the alert |
| ISO / VHD mounted content, 7-Zip/WinRAR extraction | Files inside lose the internet mark, so `zone_id` will be empty | `dl_match` falls back to filename; alert on the container file itself (`.iso`, `.img`, `.vhd`) with zone 3 |
| HTML smuggling | The browser builds the payload locally, so the on-disk file may still carry the mark but have no obvious network source | Use `host_url` and `referrer_url`; add network telemetry |
| Macros blocked by default on internet files | Modern campaigns favour OneNote, LNK, ISO and script files over macro documents | Opener list already includes OneNote; keep `wscript`/`cscript` rules; review the opener list yearly |
| Parent PID spoofing | The recorded parent may be false, hiding the document app | D3 and D2 do not rely on the parent; add Sysmon Event 10 (ProcessAccess) hunting if you suspect this |
| Process injection / hollowing | Malicious code runs inside a trusted process and no LOLBin spawns | Out of scope; needs Event 8/10/25 hunts or EDR |
| PowerShell obfuscation | Command-line patterns can be defeated | Enable Script Block Logging (4104) and AMSI telemetry and build a companion detection |
| Command line truncated or missing | Rules key on arguments | Raise Sysmon and Splunk field length limits; verify with section 2.3 |
| Clock skew and ingestion lag | Parent events may arrive after the child | The 5-minute lag in D1 mitigates this; widen if needed |
| Lineage store only keeps "interesting" ancestors | A benign-looking, non-user-path ancestor in the middle breaks the chain | Remove the `ancestor_filter` restriction in B1 if your KV store can handle full volume |
| Hosts with a different `host` value in Event 1 vs Event 15 | Download link will not match | Make sure both come from the same sourcetype and host naming |

---

## 17. ATT&CK coverage

| Tactic | Techniques |
|--------|------------|
| Initial access / execution | T1204.002 (user opens malicious file), T1059.001 / .005 / .007 (scripting) |
| Defence evasion | T1218 and sub-techniques (.001 CHM, .002 CPL, .003 cmstp, .004 InstallUtil, .005 mshta, .007 msiexec, .008 odbcconf, .009 regsvcs/regasm, .010 regsvr32, .011 rundll32, .013 mavinject), T1127.001 (MSBuild), T1220 (XSL), T1202 (indirect execution), T1036.003 (renamed system utilities), T1564.004 (ADS) |
| Command and control / ingress | T1105 (ingress tool transfer), T1197 (BITS jobs), T1140 (decode), T1132 (data encoding) |
| Lateral movement / execution | T1047 (WMI), T1053.005 (scheduled task) |
| Credential access | T1003.001 (LSASS via comsvcs), T1003.002 (SAM/SYSTEM save), T1003.003 (NTDS) |
| Impact | T1490 (inhibit recovery) |

---

## 18. References

1. LOLBAS Project, the catalogue of living-off-the-land binaries (lolbas-project.github.io). Use it to add new rules to `lolbin_classify`.
2. MITRE ATT&CK, attack.mitre.org.
3. SwiftOnSecurity `sysmon-config` and Olaf Hartong `sysmon-modular` on GitHub, as starting points for Sysmon configuration.
4. Red Canary Atomic Red Team on GitHub, for test cases.
5. Microsoft Sysinternals Sysmon documentation (event ID reference).

---

## Appendix: quick changelog of design decisions

1. Strip `:Zone.Identifier` from Event 15 paths before storing them, otherwise downloads never match the opened file.
2. Match on `OriginalFileName` first so renaming a binary cannot evade a rule, and add a score bonus for renaming.
3. Lineage is resolved with a lookup by `ProcessGuid`, up to five ancestors, rather than a chain of joins.
4. Threshold, allowlist and rarity are separate from rule logic so tuning never means rewriting SPL.
