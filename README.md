<link rel="shortcut icon" type="image/x-icon" href="https://thetanz.github.io/csfalcon/assets/favicon.ico">

![](https://avatars0.githubusercontent.com/u/2897191?s=90&v=4) ![](https://avatars0.githubusercontent.com/u/2446477?s=70&v=4)

<!--
this resource would not have been made possible 
without the help of the crowdstrike community on reddit 
https://www.reddit.com/r/crowdstrike
-->

# SPL/FQL Threat Hunting Reference Guide

This repository hosts a number of searches in Falcon Query Language (FQL), intended for use when hunting within Crowdstrike Falcon's Threat Graph.

These searches may not represent all data available within your tenant and searches should be reviewed before they're operationalised.

Searches may create strange values for time fields due to underlying Splunk transforming the values, this can be resolved with `convert ctime(timestamp/1000)`

> ⚠️ You'll need to login to Crowdstrike before using any of the search buttons across this repository.

CrowdStrike Community Work

* [Reddit Community](https://www.reddit.com/r/crowdstrike/)
* [Crowdstrike Splunk Threat Hunting Searches - rmccurdy](https://docs.google.com/spreadsheets/d/1RTcZsRbDsjxwmKpe3FIvSKUjBk5pR2Dlzj71QTnxAK0/edit#gid=0)
* [CrowdStrike Falcon Queries - pe3zx](https://github.com/pe3zx/crowdstrike-falcon-queries)

# Matrix

| Hygeine & Insights | Asset Management |
|---|---|
| [Thematic Map of Hosts](#cloropleth) | [Unencrypted Disks](#unencrypted) |
| [MS Office Passwords](#notapasswordvault) | [Remote Host Insights](#roamingdevs) |
| [Host Listening Ports](#ports) | [Non Primary Disk - Executables](#nonprimaryhddactivity) |

| Platform Events | Network Discovery |
|---|---|
| [Logons to the Falcon UI](#falconuilogon) | [Host Listening Services](#ports) |
| [Falcon User Account Creatiion](#falconnewuser) | [List All Host IP Addresses](#allexternalip) |
| [RTR Audit Records](#rtraudit) |

| Foundational Hunting & Response Searches | |
|--|--|
| [Local Account Creation](#newlocalaccounts) | [Scripts - Insights](#scripts)
| [DNS Requests by TLD](#dnsbytldsort) | [Executables Taking Screenshots](#screenshots) |  
| [Dynamic DNS Providers](#ddns) | [UAC Elevation Events](#uac) |
| [Local Account Usage](#localaccountuse) | [Cleartext Authentication Events](#cleartext) |
| [Device Authentication Events](#deviceauthevents) | [SMB Usage](#smb) |
| [Remote Desktop Protocol Sessions](#rdpsesh) | [DoH Activity](#doh) | 
| [Device Overview by Type](#deviceoview) | [Indicators of Interest](#ioi) |
| [Accounts Added to Local Administrative Groups](#newlocaladmin) | [Windows Authentication Events by Type](#authtypes) |
| [DNS IOC Hunting](#dnshunt) |


----
<a name="rdpsesh"></a>

## View Remote Desktop Protocol Activity

> To exclude or select a given host, add `ComputerName!=MYHOSTNAME` to the first line of this search.

> _A table is returned with the hostname, username and unique count of connections._

    event_simpleName=UserLogon LogonType_decimal=10
    | stats values(UserName) dc(UserName) AS "User Count" count(UserName) AS "Logon Count" by ComputerName
    | rename ComputerName AS Hostname, values(UserName) AS User
    | sort - "Logon Count"

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20event_simpleName%3DUserLogon%20LogonType_decimal%3D10%0A%20%20%20%20%7C%20stats%20values(UserName)%20dc(UserName)%20AS%20%22User%20Count%22%20count(UserName)%20AS%20%22Logon%20Count%22%20by%20ComputerName%0A%20%20%20%20%7C%20rename%20ComputerName%20AS%20Hostname%2C%20values(UserName)%20AS%20User%0A%20%20%20%20%7C%20sort%20-%20%22Logon%20Count%22&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-60m%40m&latest=now&sid=1605745355.11334&display.page.search.tab=statistics&display.general.type=statistics">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

<a name="ports"></a>

## Network Activity on Hosts - Listening Ports

> The `LPort` field sets the service you are investigating. In this example, we are looking for hosts that have recently started listening for remote desktop protocol, over port 3389 within the last 24 hours.

> _A table is returned with the hostname, operating system, machine domain, sitename & ou from active directory._

    index=main source=main event_simpleName=NetworkListenIP4 LPort=3389
    | dedup aid
    | lookup aid_master aid OUTPUT Version MachineDomain OU SiteName
    | table ComputerName Version MachineDomain OU SiteName 

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20index%3Dmain%20source%3Dmain%20event_simpleName%3DNetworkListenIP4%20LPort%3D3389%0A%20%20%20%20%7C%20dedup%20aid%0A%20%20%20%20%7C%20lookup%20aid_master%20aid%20OUTPUT%20Version%20MachineDomain%20OU%20SiteName%0A%20%20%20%20%7C%20table%20ComputerName%20Version%20MachineDomain%20OU%20SiteName&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-24h%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1605745761.11340">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

<a name="nonprimaryhddactivity"></a>

## Executable Activity Outside of Primary HDD Partition

> :warning: **under construction 🚧**

> This search intends to discover executables running from removable media - more work required to identify with HarddiskVolume*

    event_simpleName=ProcessRollup* ImageFileName!="\Device\HarddiskVolume1\*"
    | table _time ComputerName aip FileName CommandLine
    | rename ComputerName as Hostname,aip as "External IP",FileName as File,CommandLine as Command     

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20event_simpleName%3DProcessRollup*%20ImageFileName!%3D%22%5CDevice%5CHarddiskVolume1%5C*%22%0A%7C%20table%20_time%20ComputerName%20aip%20FileName%20CommandLine%0A%7C%20rename%20ComputerName%20as%20Hostname%2Caip%20as%20%22External%20IP%22%2CFileName%20as%20File%2CCommandLine%20as%20Command&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600165731.17950">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---
<a name="falconuilogon"></a>

## Logons to the Falcon UI 

> Dependant on your CrowdStrike Configuration, This search may need to be modified to accomodate for MSSP and switching account setup.

> _This will return a list of CrowdStrike users, MFA history, login IP's and geolocations to a unique count of attempts. If SSO is enabled, the Identity Provider is listed._

    index=json source=PlatformEvents
    | search (OperationName=twoFactorAuthenticate OR OperationName=saml2Assert)
    | iplocation UserIp | stats Count by UserId, Success, UserIp, City, Country, timestamp, OperationName
    | rename Count AS "Attempts",UserId AS "Username",UserIp AS "Source IP", OperationName AS Method
    | rename timestamp AS "GMT Timestamp",Success AS "Successful Authorization"
    | replace saml2Assert WITH AzureAD IN Method 
    | replace twoFactorAuthenticate WITH "Local Auth 2FA" IN Method

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20index%3Djson%20source%3DPlatformEvents%0A%7C%20search%20(OperationName%3DtwoFactorAuthenticate%20OR%20OperationName%3Dsaml2Assert)%0A%7C%20iplocation%20UserIp%20%7C%20stats%20Count%20by%20UserId%2C%20Success%2C%20UserIp%2C%20City%2C%20Country%2C%20timestamp%2C%20OperationName%0A%7C%20rename%20Count%20AS%20%22Attempts%22%2CUserId%20AS%20%22Username%22%2CUserIp%20AS%20%22Source%20IP%22%2C%20OperationName%20AS%20Method%0A%7C%20rename%20timestamp%20AS%20%22GMT%20Timestamp%22%2CSuccess%20AS%20%22Successful%20Authorization%22%0A%7C%20replace%20saml2Assert%20WITH%20AzureAD%20IN%20Method%20%0A%7C%20replace%20twoFactorAuthenticate%20WITH%20%22Local%20Auth%202FA%22%20IN%20Method&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600161003.15372">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

<a name="falconnewuser"></a>

## Falcon User Account Creation

> Dependant on your CrowdStrike Configuration, This search may need to be modified to accomodate for MSSP and switching account setups.

    index=json EventType=Event_ExternalApiEvent OperationName=CreateApiClient OR OperationName=createUser Success=true
    | table OperationName,ServiceName,UserId,AuditKeyValues{}.ValueString
    | rename OperationName as Action,ServiceName as Service,UserId as User,AuditKeyValues{}.ValueString as "New User ID"

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20index%3Djson%20EventType%3DEvent_ExternalApiEvent%20OperationName%3DCreateApiClient%20OR%20OperationName%3DcreateUser%20Success%3Dtrue%0A%7C%20table%20OperationName%2CServiceName%2CUserId%2CAuditKeyValues%7B%7D.ValueString%0A%7C%20rename%20OperationName%20as%20Action%2CServiceName%20as%20Service%2CUserId%20as%20User%2CAuditKeyValues%7B%7D.ValueString%20as%20%22New%20User%20ID%22&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-30d%40d&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600161173.15377">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

<a name="rtraudit"></a>

## RTR Audit Records

> _This will return a list of RTR sessions by the initiating user, hostname with a unique session count._

    source=PlatformEvents | spath EventType | search EventType=Event_ExternalApiEvent 
    | spath ExternalApiType | search ExternalApiType=Event_RemoteResponseSessionStartEvent
    | stats Count by HostnameField, UserName | table Count HostnameField, UserName
    | rename Count AS "RTR Sessions",HostnameField AS Hostname,UserName AS Analyst

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20source%3DPlatformEvents%20%7C%20spath%20EventType%20%7C%20search%20EventType%3DEvent_ExternalApiEvent%20%0A%7C%20spath%20ExternalApiType%20%7C%20search%20ExternalApiType%3DEvent_RemoteResponseSessionStartEvent%0A%7C%20stats%20Count%20by%20HostnameField%2C%20UserName%20%7C%20table%20Count%20HostnameField%2C%20UserName%0A%7C%20rename%20Count%20AS%20%22RTR%20Sessions%22%2CHostnameField%20AS%20Hostname%2CUserName%20AS%20Analyst&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-3d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600161458.17855">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---
<a name="allexternalip"></a>

## List All Sensor IP Addresses

> The task of obtaining a list of all external IP addresses associated to managed devices is more commonly completed through the Falcon API but can also be done through the UI with the below search.

    index=main source=main | dedup "Agent IP" 
    | table "Agent IP" | rename "Agent IP" as "External Address"

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20index%3Dmain%20source%3Dmain%20%7C%20dedup%20%22Agent%20IP%22%20%7C%20table%20%22Agent%20IP%22%20%7C%20rename%20%22Agent%20IP%22%20as%20%22External%20Address%22&sid=1600161468.17856&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-15m&latest=now&display.page.search.tab=statistics&display.general.type=statistics">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

<a name="newlocalaccounts"></a>

## Local Account Creation

> View a list of Windows accounts that have been created locally on devices within a given timeframe. 

    earliest=-7d
    index=main event_simpleName=UserAccountCreated 
    | stats values(UserName) by aid, ComputerName 

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20earliest%3D-7d%0Aindex%3Dmain%20event_simpleName%3DUserAccountCreated%20%0A%7C%20stats%20values(UserName)%20by%20aid%2C%20ComputerName%20&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-30d%40d&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.statistics.format.0=color&display.statistics.format.0.scale=minMidMax&display.statistics.format.0.colorPalette=minMidMax&display.statistics.format.0.colorPalette.minColor=%23FFFFFF&display.statistics.format.0.colorPalette.maxColor=%23D6563C&display.statistics.format.0.field=Logon%20Count&sid=1600164786.17919">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

<a name="newlocaladmin"></a>

## Accounts Added to Local Administrative Groups

> This search creates a table showing Local Security Group modifications. A table is returned with timestamps, hostnames and group names by the initiating user.

    earliest=-7d
    index=main event_simpleName=UserAccountAddedToGroup
    | eval GroupRid_dec=tonumber(ltrim(tostring(GroupRid), "0"), 16) | lookup grouprid_wingroup.csv GroupRid_dec OUTPUT WinGroup
    | convert ctime(ContextTimeStamp_decimal) AS GroupMoveTime | join aid, UserRid 
        [search event_simpleName=UserAccountCreated]
    | convert ctime(ContextTimeStamp_decimal) AS UserCreateTime | table UserCreateTime UserName GroupMoveTime WinGroup ComputerName
    | rename UserCreateTime as "Creation Time",UserName as Username,GroupMoveTime as "Group Add Time"
    | rename WinGroup as "Local Security Group",ComputerName as Hostname 

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20earliest%3D-7d%0Aindex%3Dmain%20event_simpleName%3DUserAccountAddedToGroup%0A%7C%20eval%20GroupRid_dec%3Dtonumber(ltrim(tostring(GroupRid)%2C%20%220%22)%2C%2016)%20%7C%20lookup%20grouprid_wingroup.csv%20GroupRid_dec%20OUTPUT%20WinGroup%0A%7C%20convert%20ctime(ContextTimeStamp_decimal)%20AS%20GroupMoveTime%20%7C%20join%20aid%2C%20UserRid%20%0A%20%20%20%20%5Bsearch%20event_simpleName%3DUserAccountCreated%5D%0A%7C%20convert%20ctime(ContextTimeStamp_decimal)%20AS%20UserCreateTime%20%7C%20table%20UserCreateTime%20UserName%20GroupMoveTime%20WinGroup%20ComputerName%0A%7C%20rename%20UserCreateTime%20as%20%22Creation%20Time%22%2CUserName%20as%20Username%2CGroupMoveTime%20as%20%22Group%20Add%20Time%22%0A%7C%20rename%20WinGroup%20as%20%22Local%20Security%20Group%22%2CComputerName%20as%20Hostname&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-30d%40d&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.statistics.format.0=color&display.statistics.format.0.scale=minMidMax&display.statistics.format.0.colorPalette=minMidMax&display.statistics.format.0.colorPalette.minColor=%23FFFFFF&display.statistics.format.0.colorPalette.maxColor=%23D6563C&display.statistics.format.0.field=Logon%20Count&sid=1600164822.17921">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---
<a name="localaccountuse"></a>

## Local Account Usage

> View logon activity from local accounts on a Windows system (non-domain accounts). Exclusions should be added _with care_ noting the below `UserName!=` operator

    index=main event_simpleName=UserLogon source=main host="localhost:8088" sourcetype="UserLogonV*"
    UserName!=svc_VeeamBackup UserName!=".NET*" UserName!="Microsoft Dynamics NAV 2017*" UserName!=MSSQLSERVER* UserName!="SQL*"  UserName!="*$"
    | where (ComputerName = LogonDomain)
    | stats count by ComputerName,LogonDomain,UserName | rename  ComputerName as Hostname,LogonDomain as Domain,UserName as Username,count as Count     

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20index%3Dmain%20event_simpleName%3DUserLogon%20source%3Dmain%20host%3D%22localhost%3A8088%22%20sourcetype%3D%22UserLogonV*%22%0AUserName!%3Dsvc_VeeamBackup%20UserName!%3D%22.NET*%22%20UserName!%3D%22Microsoft%20Dynamics%20NAV%202017*%22%20UserName!%3DMSSQLSERVER*%20UserName!%3D%22SQL*%22%20%20UserName!%3D%22*%24%22%0A%7C%20where%20(ComputerName%20%3D%20LogonDomain)%0A%7C%20stats%20count%20by%20ComputerName%2CLogonDomain%2CUserName%20%7C%20rename%20%20ComputerName%20as%20Hostname%2CLogonDomain%20as%20Domain%2CUserName%20as%20Username%2Ccount%20as%20Count&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600165480.17943">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---
<a name="notapasswordvault"></a>

## Microsoft Office Password Hunting

> An excercise in hygiene.

    index=main ImageFileName="*Office*" event_simpleName=*ProcessRollup2 
    | search password 
    | table  ComputerName SourceFileName ImageFileName CommandLine, UserName  

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20index%3Dmain%20ImageFileName%3D%22*Office*%22%20event_simpleName%3D*ProcessRollup2%20%0A%7C%20%20search%20password%20%0A%7C%20table%20%20ComputerName%20SourceFileName%20ImageFileName%20CommandLine%2C%20UserName%20&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600165879.17961">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---
<a name="roamingdevs"></a>

## Remote Device Insights

> This search is intended to visualise and represent your managed devices currently off location. Replace the values within `aip!=0.0.0.0` to any known address ranges.

    index=main source=main 
    | iplocation aip
    | search aip!=0.0.0.0
    | lookup aid_master aid OUTPUT Version
    | search NOT (UserName="*$" OR Version="Windows Server *")
    | dedup UserName
    | table ComputerName,UserName,City,Country,aip,Version
    | rename  aip as "IP",count(aip) as Count,ComputerName as Hostname,values(Version) as "Windows Version",UserName as User 

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20index%3Dmain%20source%3Dmain%20%0A%20%20%20%20%7C%20iplocation%20aip%0A%20%20%20%20%7C%20search%20aip!%3D0.0.0.0%0A%20%20%20%20%7C%20lookup%20aid_master%20aid%20OUTPUT%20Version%0A%20%20%20%20%7C%20search%20NOT%20(UserName%3D%22*%24%22%20OR%20Version%3D%22Windows%20Server%20*%22)%0A%20%20%20%20%7C%20dedup%20UserName%0A%20%20%20%20%7C%20table%20ComputerName%2CUserName%2CCity%2CCountry%2Caip%2CVersion%0A%20%20%20%20%7C%20rename%20%20aip%20as%20%22IP%22%2Ccount(aip)%20as%20Count%2CComputerName%20as%20Hostname%2Cvalues(Version)%20as%20%22Windows%20Version%22%2CUserName%20as%20User%20&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-3d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1607576074.25065">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

<a name="dnsbytldsort"></a>

## DNS Requests sorted by Top-Level Domain

> Outputs a table containing the TLD, FQDN's from DNS data, by count of unique domains.

    event_simpleName=DnsRequest 
    | rex field=DomainName "[@\.](?<domain>\w+\.\w+)$"
    | stats count(domain) AS "Hits" dc(DomainName) values(DomainName) by domain
    | rename domain AS "TLD", dc(DomainName) AS "Unique Domains", values(DomainName) AS "FQDN"
    | sort - Hits

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20event_simpleName%3DDnsRequest%20%0A%7C%20rex%20field%3DDomainName%20%22%5B%40%5C.%5D(%3F%3Cdomain%3E%5Cw%2B%5C.%5Cw%2B)%24%22%0A%7C%20stats%20count(domain)%20AS%20%22Hits%22%20dc(DomainName)%20values(DomainName)%20by%20domain%0A%7C%20rename%20domain%20AS%20%22TLD%22%2C%20dc(DomainName)%20AS%20%22Unique%20Domains%22%2C%20values(DomainName)%20AS%20%22FQDN%22%0A%7C%20sort%20-%20Hits%20&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600165947.17967">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---
<a name="ddns"></a>

## Dynamic DNS Providers

> Searching for the use of Dynamic DNS Providers through fields set in the `DomainName` value for the `eval` expression below.

    index=main eventtype=eam (ProcessRollup2 OR SyntheticProcessRollup2) cid=* 
    [ search eventtype=eam (DnsRequest OR SuspiciousDnsRequest) cid=* 
    [| stats count 
    | eval DomainName="*everydns *easydns* *staticip.io *dioadns.net *routeable.org *dnsdynamic.org *changeip.com *dnsmadeeasy* *dyn.com *clouddns* *now-ip.com* *freedns* *afraid.org *spdyn.de *dyndns* *duckdns* *no-ip.com *noip.com *dynu.com *duiadns.net *myonlineportal.com *dns4e.com *gslb.me *system-ns.com *dnsexit.com *nubem.com *dtdns.com *nsupdate.info *dnsomatic.com *x24hr.com *tzo.com *3322.net *serverthuis.com *dtdns.net *pubyun.com"
    | makemv DomainName delim=" " 
    | fields DomainName ] 
    | eval DomainName=lower(DomainName) 
    | rename ContextProcessId_decimal AS TargetProcessId_decimal 
    | table aid, TargetProcessId_decimal ] 
    | join TargetProcessId_decimal, aid 
    [ search eventtype=eam (DnsRequest OR SuspiciousDnsRequest) cid=* 
    [| stats count 
    | eval DomainName="*everydns *easydns* *staticip.io *dioadns.net *routeable.org *dnsdynamic.org *changeip.com *dnsmadeeasy* *dyn.com *clouddns* *now-ip.com* *freedns* *afraid.org *spdyn.de *dyndns* *duckdns* *no-ip.com *noip.com *dynu.com *duiadns.net *myonlineportal.com *dns4e.com *gslb.me *system-ns.com *dnsexit.com *nubem.com *dtdns.com *nsupdate.info *dnsomatic.com *x24hr.com *tzo.com *3322.net *serverthuis.com *dtdns.net *pubyun.com"
    | makemv DomainName delim=" " 
    | fields DomainName ] 
    | eval DomainName=lower(DomainName) 
    | rename ContextProcessId_decimal AS TargetProcessId_decimal 
    | table DomainName, aid, TargetProcessId_decimal ] 
    | stats values(ComputerName) AS "Host Name", values(UserName) AS "User Name", max(_time) AS TimeUTC by DomainName, FileName, SHA256HashData 
    | eval fStart=TimeUTC-3600 
    | eval fEnd=TimeUTC+3600 
    | table TimeUTC, DomainName, "Host Name", "User Name", FileName, SHA256HashData 
    | rename SHA256HashData AS SHA256, FileName AS "File Name", DomainName AS "Domain Name", TimeUTC AS "Time (UTC)" 
    | sort 0 -"Time (UTC)" 
    |  fieldformat "Time (UTC)"=strftime('Time (UTC)', "%Y-%m-%d %H:%M.%S")

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20event_simpleName%3DDnsRequest%20%0A%7C%20rex%20field%3DDomainName%20%22%5B%40%5C.%5D(%3F%3Cdomain%3E%5Cw%2B%5C.%5Cw%2B)%24%22%0A%7C%20stats%20count(domain)%20AS%20%22Hits%22%20dc(DomainName)%20values(DomainName)%20by%20domainindex%3Dmain%20eventtype%3Deam%20(ProcessRollup2%20OR%20SyntheticProcessRollup2)%20cid%3D*%20%0A%5B%20search%20eventtype%3Deam%20(DnsRequest%20OR%20SuspiciousDnsRequest)%20cid%3D*%20%0A%5B%7C%20stats%20count%20%0A%7C%20eval%20DomainName%3D%22*everydns%20*easydns*%20*staticip.io%20*dioadns.net%20*routeable.org%20*dnsdynamic.org%20*changeip.com%20*dnsmadeeasy*%20*dyn.com%20*clouddns*%20*now-ip.com*%20*freedns*%20*afraid.org%20*spdyn.de%20*dyndns*%20*duckdns*%20*no-ip.com%20*noip.com%20*dynu.com%20*duiadns.net%20*myonlineportal.com%20*dns4e.com%20*gslb.me%20*system-ns.com%20*dnsexit.com%20*nubem.com%20*dtdns.com%20*nsupdate.info%20*dnsomatic.com%20*x24hr.com%20*tzo.com%20*3322.net%20*serverthuis.com%20*dtdns.net%20*pubyun.com%22%0A%7C%20makemv%20DomainName%20delim%3D%22%20%22%20%0A%7C%20fields%20DomainName%20%5D%20%0A%7C%20eval%20DomainName%3Dlower(DomainName)%20%0A%7C%20rename%20ContextProcessId_decimal%20AS%20TargetProcessId_decimal%20%0A%7C%20table%20aid%2C%20TargetProcessId_decimal%20%5D%20%0A%7C%20join%20TargetProcessId_decimal%2C%20aid%20%0A%5B%20search%20eventtype%3Deam%20(DnsRequest%20OR%20SuspiciousDnsRequest)%20cid%3D*%20%0A%5B%7C%20stats%20count%20%0A%7C%20eval%20DomainName%3D%22*everydns%20*easydns*%20*staticip.io%20*dioadns.net%20*routeable.org%20*dnsdynamic.org%20*changeip.com%20*dnsmadeeasy*%20*dyn.com%20*clouddns*%20*now-ip.com*%20*freedns*%20*afraid.org%20*spdyn.de%20*dyndns*%20*duckdns*%20*no-ip.com%20*noip.com%20*dynu.com%20*duiadns.net%20*myonlineportal.com%20*dns4e.com%20*gslb.me%20*system-ns.com%20*dnsexit.com%20*nubem.com%20*dtdns.com%20*nsupdate.info%20*dnsomatic.com%20*x24hr.com%20*tzo.com%20*3322.net%20*serverthuis.com%20*dtdns.net%20*pubyun.com%22%0A%7C%20makemv%20DomainName%20delim%3D%22%20%22%20%0A%7C%20fields%20DomainName%20%5D%20%0A%7C%20eval%20DomainName%3Dlower(DomainName)%20%0A%7C%20rename%20ContextProcessId_decimal%20AS%20TargetProcessId_decimal%20%0A%7C%20table%20DomainName%2C%20aid%2C%20TargetProcessId_decimal%20%5D%20%0A%7C%20stats%20values(ComputerName)%20AS%20%22Host%20Name%22%2C%20values(UserName)%20AS%20%22User%20Name%22%2C%20max(_time)%20AS%20TimeUTC%20by%20DomainName%2C%20FileName%2C%20SHA256HashData%20%0A%7C%20eval%20fStart%3DTimeUTC-3600%20%0A%7C%20eval%20fEnd%3DTimeUTC%2B3600%20%0A%7C%20table%20TimeUTC%2C%20DomainName%2C%20%22Host%20Name%22%2C%20%22User%20Name%22%2C%20FileName%2C%20SHA256HashData%20%0A%7C%20rename%20SHA256HashData%20AS%20SHA256%2C%20FileName%20AS%20%22File%20Name%22%2C%20DomainName%20AS%20%22Domain%20Name%22%2C%20TimeUTC%20AS%20%22Time%20(UTC)%22%20%0A%7C%20sort%200%20-%22Time%20(UTC)%22%20%0A%7C%20%20fieldformat%20%22Time%20(UTC)%22%3Dstrftime(%27Time%20(UTC)%27%2C%20%22%25Y-%25m-%25d%20%25H%3A%25M.%25S%22)%0A%0A%7C%20rename%20domain%20AS%20%22TLD%22%2C%20dc(DomainName)%20AS%20%22Unique%20Domains%22%2C%20values(DomainName)%20AS%20%22FQDN%22%0A%7C%20sort%20-%20Hits%20&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600166016.17968">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---
<a name="dnshunt"></a>
## DNS IOC Hunt

> Searching for the use of a single DNS domain through fields set in the `DomainName` value for the `eval` expression below. Same Query as the Dynamic DNS providers but indended for faster hunting of single known IOCs

    index=main eventtype=eam (ProcessRollup2 OR SyntheticProcessRollup2) cid=* 
    [ search eventtype=eam (DnsRequest OR SuspiciousDnsRequest) cid=* 
    [| stats count 
    | eval DomainName="<DOMAIN.COM GOES HERE>"
    | makemv DomainName delim=" " 
    | fields DomainName ] 
    | eval DomainName=lower(DomainName) 
    | rename ContextProcessId_decimal AS TargetProcessId_decimal 
    | table aid, TargetProcessId_decimal ] 
    | join TargetProcessId_decimal, aid 
    [ search eventtype=eam (DnsRequest OR SuspiciousDnsRequest) cid=* 
    [| stats count 
    | eval DomainName="<DOMAIN.COM GOES HERE>"
    | makemv DomainName delim=" " 
    | fields DomainName ] 
    | eval DomainName=lower(DomainName) 
    | rename ContextProcessId_decimal AS TargetProcessId_decimal 
    | table DomainName, aid, TargetProcessId_decimal ] 
    | stats values(ComputerName) AS "Host Name", values(UserName) AS "User Name", max(_time) AS TimeUTC by DomainName, FileName, SHA256HashData 
    | eval fStart=TimeUTC-3600 
    | eval fEnd=TimeUTC+3600 
    | table TimeUTC, DomainName, "Host Name", "User Name", FileName, SHA256HashData 
    | rename SHA256HashData AS SHA256, FileName AS "File Name", DomainName AS "Domain Name", TimeUTC AS "Time (UTC)" 
    | sort 0 -"Time (UTC)" 
    |  fieldformat "Time (UTC)"=strftime('Time (UTC)', "%Y-%m-%d %H:%M.%S")

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?earliest=-3d%40h&latest=now&q=search%20index%3Dmain%20eventtype%3Deam%20(ProcessRollup2%20OR%20SyntheticProcessRollup2)%20cid%3D*%20%0A%5B%20search%20eventtype%3Deam%20(DnsRequest%20OR%20SuspiciousDnsRequest)%20cid%3D*%20%0A%5B%7C%20stats%20count%20%0A%7C%20eval%20DomainName%3D%22bussinessfile.notelet.so%22%0A%7C%20makemv%20DomainName%20delim%3D%22%20%22%20%0A%7C%20fields%20DomainName%20%5D%20%0A%7C%20eval%20DomainName%3Dlower(DomainName)%20%0A%7C%20rename%20ContextProcessId_decimal%20AS%20TargetProcessId_decimal%20%0A%7C%20table%20aid%2C%20TargetProcessId_decimal%20%5D%20%0A%7C%20join%20TargetProcessId_decimal%2C%20aid%20%0A%5B%20search%20eventtype%3Deam%20(DnsRequest%20OR%20SuspiciousDnsRequest)%20cid%3D*%20%0A%5B%7C%20stats%20count%20%0A%7C%20eval%20DomainName%3D%22bussinessfile.notelet.so%22%0A%7C%20makemv%20DomainName%20delim%3D%22%20%22%20%0A%7C%20fields%20DomainName%20%5D%20%0A%7C%20eval%20DomainName%3Dlower(DomainName)%20%0A%7C%20rename%20ContextProcessId_decimal%20AS%20TargetProcessId_decimal%20%0A%7C%20table%20DomainName%2C%20aid%2C%20TargetProcessId_decimal%20%5D%20%0A%7C%20stats%20values(ComputerName)%20AS%20%22Host%20Name%22%2C%20values(UserName)%20AS%20%22User%20Name%22%2C%20max(_time)%20AS%20TimeUTC%20by%20DomainName%2C%20FileName%2C%20SHA256HashData%20%0A%7C%20eval%20fStart%3DTimeUTC-3600%20%0A%7C%20eval%20fEnd%3DTimeUTC%2B3600%20%0A%7C%20table%20TimeUTC%2C%20DomainName%2C%20%22Host%20Name%22%2C%20%22User%20Name%22%2C%20FileName%2C%20SHA256HashData%20%0A%7C%20rename%20SHA256HashData%20AS%20SHA256%2C%20FileName%20AS%20%22File%20Name%22%2C%20DomainName%20AS%20%22Domain%20Name%22%2C%20TimeUTC%20AS%20%22Time%20(UTC)%22%20%0A%7C%20sort%200%20-%22Time%20(UTC)%22%20%0A%7C%20%20fieldformat%20%22Time%20(UTC)%22%3Dstrftime(%27Time%20(UTC)%27%2C%20%22%25Y-%25m-%25d%20%25H%3A%25M.%25S%22)&display.page.search.mode=verbose&dispatch.sample_ratio=1&display.page.search.tab=statistics&display.general.type=statistics&sid=1615344224.12482">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>
 
---
<a name="deviceauthevents"></a>

## Device Authentication Events

> View Windows authentication events by domain, authentication package, domain controller / logon server, package & principal

    event_simpleName=UserLogon LogonType_decimal=10 UserIsAdmin_decimal=1 
    | lookup aid_master aid OUTPUT Version
    | convert ctime(LogonTime_decimal)
    | fillnull value="N/A" UserPrincipal
    | table ComputerName Version LogonTime_decimal UserName UserPrincipal LogonServer LogonDomain AuthenticationPackage
    | rename ComputerName AS Endpoint, Version AS "Operating System", LogonTime_decimal AS "Logon Time", UserName AS User, UserPrincipal AS Principal, LogonServer AS "Logon Server", LogonDomain AS Domain, AuthenticationPackage AS "Auth Package" 

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20event_simpleName%3DUserLogon%20LogonType_decimal%3D10%20UserIsAdmin_decimal%3D1%20%0A%7C%20lookup%20aid_master%20aid%20OUTPUT%20Version%0A%7C%20convert%20ctime(LogonTime_decimal)%0A%7C%20fillnull%20value%3D%22N%2FA%22%20UserPrincipal%0A%7C%20table%20ComputerName%20Version%20LogonTime_decimal%20UserName%20UserPrincipal%20LogonServer%20LogonDomain%20AuthenticationPackage%0A%7C%20rename%20ComputerName%20AS%20Endpoint%2C%20Version%20AS%20%22Operating%20System%22%2C%20LogonTime_decimal%20AS%20%22Logon%20Time%22%2C%20UserName%20AS%20User%2C%20UserPrincipal%20AS%20Principal%2C%20LogonServer%20AS%20%22Logon%20Server%22%2C%20LogonDomain%20AS%20Domain%2C%20AuthenticationPackage%20AS%20%22Auth%20Package%22%20&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600166081.17970">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

<a name="doh"></a>

## DNS Over HTTPS Usage

> Searching for DoH usage by the original, UDP request sent to the nameserver.

    index=main eventtype=eam (ProcessRollup2 OR SyntheticProcessRollup2) cid=*
    [ search eventtype=eam (DnsRequest OR SuspiciousDnsRequest) cid=*
    [| stats count
    | eval DomainName="2.dnscrypt-cert.oszx.co doh-fi.blahdns.com doh-de.blahdns.com doh-jp.blahdns.com adblock.mydns.network adult-filter-dns.cleanbrowsing.org cloudflare-dns.com commons.host dns-family.adguard.com dns-nyc.aaflalo.me dns.aa.net.uk dns.aaflalo.me dns.adguard.com dns.containerpi.com dns.digitale-gesellschaft.ch dns.dns-over-https.com dns.dnsoverhttps.net dns.flatuslifir.is dns.google dns.hostux.net dns.nextdns.io dns.oszx.co dns.quad9.net dns.rubyfish.cn dns.twnic.tw dns10.quad9.net dns11.quad9.net dns9.quad9.net doh-2.seby.io doh.42l.fr doh.applied-privacy.net doh.armadillodns.net doh.captnemo.in doh.centraleu.pi-dns.com doh.cleanbrowsing.org doh.crypto.sx doh.dns.sb doh.dnslify.com doh.dnswarden.com doh.eastus.pi-dns.com doh.familyshield.opendns.com doh.ffmuc.net doh.li doh.libredns.gr doh.northeu.pi-dns.com doh.opendns.com doh.powerdns.org doh.securedns.eu doh.tiar.app doh.tiarap.org doh.westus.pi-dns.com doh.xfinity.com dohdot.coxlab.net dot.xfinity.com example.doh.blockerdns.com family-filter-dns.cleanbrowsing.org family.canadianshield.cira.ca family.cloudflare-dns.com ibksturm.synology.me ibuki.cgnat.net jcdns.fun jp.tiar.app jp.tiarap.org mozilla.cloudflare-dns.com ns.hostux.net odvr.nic.cz private.canadianshield.cira.ca protected.canadianshield.cira.ca rdns.faelix.net security-filter-dns.cleanbrowsing.org security.cloudflare-dns.com"
    | makemv DomainName delim=" "
    | fields DomainName ]
    | eval DomainName=lower(DomainName)
    | rename ContextProcessId_decimal AS TargetProcessId_decimal
    | table aid, TargetProcessId_decimal ]
    | join TargetProcessId_decimal, aid
    [ search eventtype=eam (DnsRequest OR SuspiciousDnsRequest) cid=*
    [| stats count
    | eval DomainName="2.dnscrypt-cert.oszx.co doh-fi.blahdns.com doh-de.blahdns.com doh-jp.blahdns.com adblock.mydns.network adult-filter-dns.cleanbrowsing.org cloudflare-dns.com commons.host dns-family.adguard.com dns-nyc.aaflalo.me dns.aa.net.uk dns.aaflalo.me dns.adguard.com dns.containerpi.com dns.digitale-gesellschaft.ch dns.dns-over-https.com dns.dnsoverhttps.net dns.flatuslifir.is dns.google dns.hostux.net dns.nextdns.io dns.oszx.co dns.quad9.net dns.rubyfish.cn dns.twnic.tw dns10.quad9.net dns11.quad9.net dns9.quad9.net doh-2.seby.io doh.42l.fr doh.applied-privacy.net doh.armadillodns.net doh.captnemo.in doh.centraleu.pi-dns.com doh.cleanbrowsing.org doh.crypto.sx doh.dns.sb doh.dnslify.com doh.dnswarden.com doh.eastus.pi-dns.com doh.familyshield.opendns.com doh.ffmuc.net doh.li doh.libredns.gr doh.northeu.pi-dns.com doh.opendns.com doh.powerdns.org doh.securedns.eu doh.tiar.app doh.tiarap.org doh.westus.pi-dns.com doh.xfinity.com dohdot.coxlab.net dot.xfinity.com example.doh.blockerdns.com family-filter-dns.cleanbrowsing.org family.canadianshield.cira.ca family.cloudflare-dns.com ibksturm.synology.me ibuki.cgnat.net jcdns.fun jp.tiar.app jp.tiarap.org mozilla.cloudflare-dns.com ns.hostux.net odvr.nic.cz private.canadianshield.cira.ca protected.canadianshield.cira.ca rdns.faelix.net security-filter-dns.cleanbrowsing.org security.cloudflare-dns.com"
    | makemv DomainName delim=" "
    | fields DomainName ]
    | eval DomainName=lower(DomainName)
    | rename ContextProcessId_decimal AS TargetProcessId_decimal
    | table DomainName, aid, TargetProcessId_decimal ]
    | stats values(ComputerName) AS "Host Name", values(UserName) AS "User Name", max(_time) AS TimeUTC by DomainName, FileName, SHA256HashData
    | eval fStart=TimeUTC-3600
    | eval fEnd=TimeUTC+3600
    | table TimeUTC, DomainName, "Host Name", "User Name", FileName, SHA256HashData
    | rename SHA256HashData AS SHA256, FileName AS "File Name", DomainName AS "Domain Name", TimeUTC AS "Time (UTC)"
    | sort 0 -"Time (UTC)"
    |  fieldformat "Time (UTC)"=strftime('Time (UTC)', "%Y-%m-%d %H:%M.%S")     

---
<a name="deviceoview"></a>

## Device Overview by Type

> A visual Representation of Servers, macOS Devices, Windows Endpoints & Domain Controllers

    | inputlookup aid_master `hideHiddenHosts()` 
    | search NOT (AgentLoadFlags=null AgentLoadFlags=Workstations)
    | stats count BY ProductType
    | rename ProductType AS type
    | replace none WITH macOS IN type
    | replace 1 WITH "windows workstations" IN type
    | replace 2 WITH "domain controllers" IN type
    | replace 3 WITH "servers" IN type
 
<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=%7C%20inputlookup%20aid_master%20%60hideHiddenHosts()%60%20%0A%7C%20search%20NOT%20(AgentLoadFlags%3Dnull%20AgentLoadFlags%3DWorkstations)%0A%7C%20stats%20count%20BY%20ProductType%0A%7C%20rename%20ProductType%20AS%20type%0A%7C%20replace%20none%20WITH%20macOS%20IN%20type%0A%7C%20replace%201%20WITH%20%22windows%20workstations%22%20IN%20type%0A%7C%20replace%202%20WITH%20%22domain%20controllers%22%20IN%20type%0A%7C%20replace%203%20WITH%20%22servers%22%20IN%20type%0A&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600166264.17973">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---
<a name="cloropleth"></a>

## View Devices on a Map

> After running this search head to the `Visualisations` tab and select `Cloropleth`  to view hthe coordinates represented

    index=main
    | table aip
    | iplocation aip
    | stats count by Country
    | geom geo_countries allFeatures=True featureIdField=Country  

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%0A%7C%20table%20aip%0A%7C%20iplocation%20aip%0A%7C%20stats%20count%20by%20Country%0A%7C%20geom%20geo_countries%20allFeatures%3DTrue%20featureIdField%3DCountry%20&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=visualizations&display.general.type=visualizations&sid=1600166281.17975&display.visualizations.type=mapping&display.visualizations.mapping.type=choropleth">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---
<a name="smb"></a>

## SMB File Share Usage & Statistics

> View SMB actions by client, server, fileshare name and count of operations

    index=main sourcetype="SmbClientShareOpenedEtwV1-v02"
    | rename event_simpleName AS Action,ClientComputerName AS Server,ComputerName AS Client,SmbShareName AS "Share Name"
    | replace SmbClientShareOpenedEtw WITH "SMB Share Opened" IN Action
    | search NOT (Server=localhost)
    | stats count by Action,Client,Server,"Share Name"

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%20sourcetype%3D%22SmbClientShareOpenedEtwV1-v02%22%0A%7C%20rename%20event_simpleName%20AS%20Action%2CClientComputerName%20AS%20Server%2CComputerName%20AS%20Client%2CSmbShareName%20AS%20%22Share%20Name%22%0A%7C%20replace%20SmbClientShareOpenedEtw%20WITH%20%22SMB%20Share%20Opened%22%20IN%20Action%0A%7C%20search%20NOT%20(Server%3Dlocalhost)%0A%7C%20stats%20count%20by%20Action%2CClient%2CServer%2C%22Share%20Name%22&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.visualizations.type=mapping&display.visualizations.mapping.type=choropleth&sid=1600166379.17978">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

<a name="scripts"></a>

## Running Scripts Insights - Decoded Powershell, Bash & Zsh

> Review & hunt decoded scripts. Reccomend building an exclusion set to cater to each unique environment.

    index=main  sourcetype="ScriptControlDetectInfoV4-v02" OR sourcetype="CommandHistoryV2-v02" 
    | search NOT (ScriptContent=*LogicMonitor* OR ScriptContent="*PublicKeyToken=31bf3856ad364e35*")
    | replace CommandHistory WITH ScriptContent IN "CommandHistoryV2-v02"
    | dedup ScriptContent 
    | iplocation aip
    | table DetectDescription,ComputerName,City,ScriptContent

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%20%20sourcetype%3D%22ScriptControlDetectInfoV4-v02%22%20OR%20sourcetype%3D%22CommandHistoryV2-v02%22%20%0A%7C%20search%20NOT%20(ScriptContent%3D*LogicMonitor*%20OR%20ScriptContent%3D%22*PublicKeyToken%3D31bf3856ad364e35*%22)%0A%7C%20replace%20CommandHistory%20WITH%20ScriptContent%20IN%20%22CommandHistoryV2-v02%22%0A%7C%20dedup%20ScriptContent%20%0A%7C%20iplocation%20aip%0A%7C%20table%20DetectDescription%2CComputerName%2CCity%2CScriptContent%20&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.visualizations.type=mapping&display.visualizations.mapping.type=choropleth&sid=1600166419.17981">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---
<a name="ioi"></a>

## Indicators of Interest

> CrowdStrike Detection Metadata

    index=main source=main
    | table DetectDescription,sourcetype
    | sort DetectDescription
    | search NOT (DetectDescription="Experimental detection.")
    | stats values(sourcetype) by DetectDescription     

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%20source%3Dmain%0A%7C%20table%20DetectDescription%2Csourcetype%0A%7C%20sort%20DetectDescription%0A%7C%20search%20NOT%20(DetectDescription%3D%22Experimental%20detection.%22)%0A%7C%20stats%20values(sourcetype)%20by%20DetectDescription&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.visualizations.type=mapping&display.visualizations.mapping.type=choropleth&sid=1600166460.17983">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

<a name="uac"></a>

## UAC Elevation Events

> View UAC elevation attempts for administrative operations. 

    index=main sourcetype="UACExeElevation*"
    | iplocation aip | lookup aid_master aid OUTPUT Version
    | stats count BY ComputerName, Region, Version, UACCommandLineToValidate     

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%20sourcetype%3D%22UACExeElevation*%22%0A%7C%20iplocation%20aip%20%7C%20lookup%20aid_master%20aid%20OUTPUT%20Version%0A%7C%20stats%20count%20BY%20ComputerName%2C%20Region%2C%20Version%2C%20UACCommandLineToValidate&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.visualizations.type=mapping&display.visualizations.mapping.type=choropleth&sid=1600166535.17986">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---
<a name="screenshots"></a>

## Executables Taking Screenshots 

> Teams has been excluded and other video-conferencing solutions may need to be added to minimise the noise
    
    index=main sourcetype="ScreenshotTakenEtwV2-v02" FileName!="Teams.exe"
    |  stats count by ComputerName,UserName,FileName | rename count as Screenshots     

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%20sourcetype%3D%22ScreenshotTakenEtwV2-v02%22%20FileName!%3D%22Teams.exe%22%0A%7C%20%20stats%20count%20by%20ComputerName%2CUserName%2CFileName%20%7C%20rename%20count%20as%20Screenshots%20&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.visualizations.type=mapping&display.visualizations.mapping.type=choropleth&sid=1600166603.17992">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---
<a name="unencrypted"></a>

## Unencrypted C Drives - BitLocker Review

> Review BitLocker compliance

    | inputlookup aid_volume_encryption.csv where cid=* AND aid=* `formatDate(_time)`
    | fillnull VolumeIsEncrypted_decimal value=0
    | eval EncryptedVolume=if(VolumeIsEncrypted_decimal=1,ActualDriveLetter." ("._time.")",null()) 
    | eval UnencryptedVolume=if(VolumeIsEncrypted_decimal=0,ActualDriveLetter." ("._time.")",null())
    | stats values(EncryptedVolume) as EncryptedVolumes values(UnencryptedVolume) as UnencryptedVolumes sum(VolumeIsEncrypted_decimal) as volumes_encrypted count AS volume_count by aid 
    | eval status=if(volumes_encrypted=volume_count, "Encrypted Hosts", "Unencrypted Hosts") 
    | lookup aid_master.csv aid OUTPUT ComputerName ProductType, ChassisType, SystemManufacturer, SystemProductName, Version, OU, MachineDomain, SiteName
    | lookup chassis.csv ChassisType output Mobility
    | lookup managedassets.csv aid OUTPUT MAC, LocalAddressIP4
    | eval FormFactor=case(
        match(SystemManufacturer,"^(Parallels)|(Xen)|(VM).*"),"Virtual Machine",
        Mobility="Mobile","Laptop/Notebook",
        ProductType==1, "Workstation",
        ProductType==2, "Server Chassis",
        ProductType==3, "Server Chassis",
        true(),"Other"
        )
    | search FormFactor="Laptop/Notebook"
    | search UnencryptedVolumes="C:*"
    | table ComputerName EncryptedVolumes UnencryptedVolumes, FormFactor, SystemManufacturer, SystemProductName, Version, OU
    | rename ComputerName as "Host Name", FormFactor as "Form Factor", SystemManufacturer as "Manufacturer", SystemProductName as "Model"
    | rename EncryptedVolumes as "Encrypted Drive(s)", UnencryptedVolumes as "Unencrypted Drive(s)", LocalAddressIP4 as IP

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=%7C%20inputlookup%20aid_volume_encryption.csv%20where%20cid%3D*%20AND%20aid%3D*%20%60formatDate(_time)%60%0A%7C%20fillnull%20VolumeIsEncrypted_decimal%20value%3D0%0A%7C%20eval%20EncryptedVolume%3Dif(VolumeIsEncrypted_decimal%3D1%2CActualDriveLetter.%22%20(%22._time.%22)%22%2Cnull())%20%0A%7C%20eval%20UnencryptedVolume%3Dif(VolumeIsEncrypted_decimal%3D0%2CActualDriveLetter.%22%20(%22._time.%22)%22%2Cnull())%0A%7C%20stats%20values(EncryptedVolume)%20as%20EncryptedVolumes%20values(UnencryptedVolume)%20as%20UnencryptedVolumes%20sum(VolumeIsEncrypted_decimal)%20as%20volumes_encrypted%20count%20AS%20volume_count%20by%20aid%20%0A%7C%20eval%20status%3Dif(volumes_encrypted%3Dvolume_count%2C%20%22Encrypted%20Hosts%22%2C%20%22Unencrypted%20Hosts%22)%20%0A%7C%20lookup%20aid_master.csv%20aid%20OUTPUT%20ComputerName%20ProductType%2C%20ChassisType%2C%20SystemManufacturer%2C%20SystemProductName%2C%20Version%2C%20OU%2C%20MachineDomain%2C%20SiteName%0A%7C%20lookup%20chassis.csv%20ChassisType%20output%20Mobility%0A%7C%20lookup%20managedassets.csv%20aid%20OUTPUT%20MAC%2C%20LocalAddressIP4%0A%7C%20eval%20FormFactor%3Dcase(%0A%20%20%20%20%20%20%20match(SystemManufacturer%2C%22%5E(Parallels)%7C(Xen)%7C(VM).*%22)%2C%22Virtual%20Machine%22%2C%0A%20%20%20%20%20%20%20Mobility%3D%22Mobile%22%2C%22Laptop%2FNotebook%22%2C%0A%20%20%20%20%20%20%20ProductType%3D%3D1%2C%20%22Workstation%22%2C%0A%20%20%20%20%20%20%20ProductType%3D%3D2%2C%20%22Server%20Chassis%22%2C%0A%20%20%20%20%20%20%20ProductType%3D%3D3%2C%20%22Server%20Chassis%22%2C%0A%20%20%20%20%20%20%20true()%2C%22Other%22%0A%20%20%20%20%20%20%20)%0A%7C%20search%20FormFactor%3D%22Laptop%2FNotebook%22%0A%7C%20search%20UnencryptedVolumes%3D%22C%3A*%22%0A%7C%20table%20ComputerName%20EncryptedVolumes%20UnencryptedVolumes%2C%20FormFactor%2C%20SystemManufacturer%2C%20SystemProductName%2C%20Version%2C%20OU%0A%7C%20rename%20ComputerName%20as%20%22Host%20Name%22%2C%20FormFactor%20as%20%22Form%20Factor%22%2C%20SystemManufacturer%20as%20%22Manufacturer%22%2C%20SystemProductName%20as%20%22Model%22%0A%7C%20rename%20EncryptedVolumes%20as%20%22Encrypted%20Drive(s)%22%2C%20UnencryptedVolumes%20as%20%22Unencrypted%20Drive(s)%22%2C%20LocalAddressIP4%20as%20IP%0A&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.visualizations.type=mapping&display.visualizations.mapping.type=choropleth&sid=1600166747.17998">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

<a name="authtypes"></a>

## Windows Authentication Events by Type

> This is intended to be viewed as a pie chart. Navigate to `Visualisation` and select `Pie Chart`

    index=main event_simpleName=UserLogon 
    | rename UserName AS User, ComputerName AS Endpoint, UserSid_readable AS "User SID", LogonDomain AS "Logon Domain", LogonType_decimal AS LogonType
    | rename LogonServer AS "Logon Server", admin AS "Administrator?", values(UserName) as  Username, values(ComputerName) as Hostname
    | replace 0 WITH "0.SYSTEM" IN LogonType 
    | replace 2 WITH "2.LOCAL-INTERACTIVE" IN LogonType 
    | replace 3 WITH "3.NETWORK" IN LogonType 
    | replace 4 WITH "4.BATCH" IN LogonType
    | replace 5 WITH "5.SERVICE" IN LogonType 
    | replace 7 WITH "7.LOCALUNLOCK" IN LogonType 
    | replace 8 WITH "8.NETWORK-CLEARTEXT" IN LogonType 
    | replace 9 WITH "9.NEWCREDENTIALS" IN LogonType
    | replace 10 WITH "10.RDP-INTERACTIVE" IN LogonType 
    | replace 11 WITH "11.CACHE-INTERACTIVE" IN LogonType 
    | replace 12 WITH "12.CACHED-REMOTE-INTERACETIVE" IN LogonType
    | stats count by LogonType

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%20event_simpleName%3DUserLogon%20%0A%7C%20rename%20UserName%20AS%20User%2C%20ComputerName%20AS%20Endpoint%2C%20UserSid_readable%20AS%20%22User%20SID%22%2C%20LogonDomain%20AS%20%22Logon%20Domain%22%2C%20LogonType_decimal%20AS%20LogonType%0A%7C%20rename%20LogonServer%20AS%20%22Logon%20Server%22%2C%20admin%20AS%20%22Administrator%3F%22%2C%20values(UserName)%20as%20%20Username%2C%20values(ComputerName)%20as%20Hostname%0A%7C%20replace%200%20WITH%20%220.SYSTEM%22%20IN%20LogonType%20%0A%7C%20replace%202%20WITH%20%222.LOCAL-INTERACTIVE%22%20IN%20LogonType%20%0A%7C%20replace%203%20WITH%20%223.NETWORK%22%20IN%20LogonType%20%0A%7C%20replace%204%20WITH%20%224.BATCH%22%20IN%20LogonType%0A%7C%20replace%205%20WITH%20%225.SERVICE%22%20IN%20LogonType%20%0A%7C%20replace%207%20WITH%20%227.LOCALUNLOCK%22%20IN%20LogonType%20%0A%7C%20replace%208%20WITH%20%228.NETWORK-CLEARTEXT%22%20IN%20LogonType%20%0A%7C%20replace%209%20WITH%20%229.NEWCREDENTIALS%22%20IN%20LogonType%0A%7C%20replace%2010%20WITH%20%2210.RDP-INTERACTIVE%22%20IN%20LogonType%20%0A%7C%20replace%2011%20WITH%20%2211.CACHE-INTERACTIVE%22%20IN%20LogonType%20%0A%7C%20replace%2012%20WITH%20%2212.CACHED-REMOTE-INTERACETIVE%22%20IN%20LogonType%0A%7C%20stats%20count%20by%20LogonType%20&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=visualizations&display.general.type=visualizations&display.visualizations.type=charting&display.visualizations.mapping.type=choropleth&sid=1600166780.17999&display.visualizations.charting.chart=pie">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

<a name="cleartext"></a>

## Cleartext Authentication Events

> This search will only return events for Windows hosts 

    index=main event_simpleName=UserLogon LogonType_decimal=8
    | lookup aid_master aid OUTPUT Version
    | stats count by ComputerName, AuthenticationPackage, UserName, Version
     
<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%20event_simpleName%3DUserLogon%20LogonType_decimal%3D8%0A%7C%20lookup%20aid_master%20aid%20OUTPUT%20Version%0A%7C%20stats%20count%20by%20ComputerName%2C%20AuthenticationPackage%2C%20UserName%2C%20Version&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.visualizations.type=charting&display.visualizations.mapping.type=choropleth&display.visualizations.charting.chart=pie&display.statistics.sortColumn=count&display.statistics.sortDirection=desc&sid=1600166863.18003&display.statistics.format.0=color&display.statistics.format.0.scale=threshold&display.statistics.format.0.scale.thresholds=%5B0%2C30%2C70%2C100%5D&display.statistics.format.0.colorPalette=list&display.statistics.format.0.colorPalette.colors=%5B%2365A637%2C%236DB7C6%2C%23F7BC38%2C%23F58F39%2C%23D93F3C%5D&display.statistics.format.0.field=count">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

<a name="TagName"></a>

## SearchTitle

> SearchNotes

    SPL-FQL-Query

<a href="HTTPURLGOESHERE">
<img border="0" alt="W3Schools" src="assets/search.png" height="40"></a>

---

[Theta](https://www.theta.co.nz)
