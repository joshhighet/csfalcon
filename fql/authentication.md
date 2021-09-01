# Local Account Creation

> View a list of Windows accounts that have been created locally on devices within a given timeframe. 

    earliest=-7d
    index=main event_simpleName=UserAccountCreated 
    | stats values(UserName) by aid, ComputerName 

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20earliest%3D-7d%0Aindex%3Dmain%20event_simpleName%3DUserAccountCreated%20%0A%7C%20stats%20values(UserName)%20by%20aid%2C%20ComputerName%20&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-30d%40d&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.statistics.format.0=color&display.statistics.format.0.scale=minMidMax&display.statistics.format.0.colorPalette=minMidMax&display.statistics.format.0.colorPalette.minColor=%23FFFFFF&display.statistics.format.0.colorPalette.maxColor=%23D6563C&display.statistics.format.0.field=Logon%20Count&sid=1600164786.17919">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Cleartext Authentication Events

> This search will only return events for Windows hosts 

    index=main event_simpleName=UserLogon LogonType_decimal=8
    | lookup aid_master aid OUTPUT Version
    | stats count by ComputerName, AuthenticationPackage, UserName, Version
     
<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%20event_simpleName%3DUserLogon%20LogonType_decimal%3D8%0A%7C%20lookup%20aid_master%20aid%20OUTPUT%20Version%0A%7C%20stats%20count%20by%20ComputerName%2C%20AuthenticationPackage%2C%20UserName%2C%20Version&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.visualizations.type=charting&display.visualizations.mapping.type=choropleth&display.visualizations.charting.chart=pie&display.statistics.sortColumn=count&display.statistics.sortDirection=desc&sid=1600166863.18003&display.statistics.format.0=color&display.statistics.format.0.scale=threshold&display.statistics.format.0.scale.thresholds=%5B0%2C30%2C70%2C100%5D&display.statistics.format.0.colorPalette=list&display.statistics.format.0.colorPalette.colors=%5B%2365A637%2C%236DB7C6%2C%23F7BC38%2C%23F58F39%2C%23D93F3C%5D&display.statistics.format.0.field=count">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Accounts Added to Local Administrative Groups

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
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Local Account Usage

> View logon activity from local accounts on a Windows system (non-domain accounts). Exclusions should be added _with care_ noting the below `UserName!=` operator

    index=main event_simpleName=UserLogon source=main host="localhost:8088" sourcetype="UserLogonV*"
    UserName!=svc_VeeamBackup UserName!=".NET*" UserName!="Microsoft Dynamics NAV 2017*" UserName!=MSSQLSERVER* UserName!="SQL*"  UserName!="*$"
    | where (ComputerName = LogonDomain)
    | stats count by ComputerName,LogonDomain,UserName | rename  ComputerName as Hostname,LogonDomain as Domain,UserName as Username,count as Count     

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20index%3Dmain%20event_simpleName%3DUserLogon%20source%3Dmain%20host%3D%22localhost%3A8088%22%20sourcetype%3D%22UserLogonV*%22%0AUserName!%3Dsvc_VeeamBackup%20UserName!%3D%22.NET*%22%20UserName!%3D%22Microsoft%20Dynamics%20NAV%202017*%22%20UserName!%3DMSSQLSERVER*%20UserName!%3D%22SQL*%22%20%20UserName!%3D%22*%24%22%0A%7C%20where%20(ComputerName%20%3D%20LogonDomain)%0A%7C%20stats%20count%20by%20ComputerName%2CLogonDomain%2CUserName%20%7C%20rename%20%20ComputerName%20as%20Hostname%2CLogonDomain%20as%20Domain%2CUserName%20as%20Username%2Ccount%20as%20Count&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600165480.17943">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Device Authentication Events

> View Windows authentication events by domain, authentication package, domain controller / logon server, package & principal

    event_simpleName=UserLogon LogonType_decimal=10 UserIsAdmin_decimal=1 
    | lookup aid_master aid OUTPUT Version
    | convert ctime(LogonTime_decimal)
    | fillnull value="N/A" UserPrincipal
    | table ComputerName Version LogonTime_decimal UserName UserPrincipal LogonServer LogonDomain AuthenticationPackage
    | rename ComputerName AS Endpoint, Version AS "Operating System", LogonTime_decimal AS "Logon Time", UserName AS User, UserPrincipal AS Principal, LogonServer AS "Logon Server", LogonDomain AS Domain, AuthenticationPackage AS "Auth Package" 

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20event_simpleName%3DUserLogon%20LogonType_decimal%3D10%20UserIsAdmin_decimal%3D1%20%0A%7C%20lookup%20aid_master%20aid%20OUTPUT%20Version%0A%7C%20convert%20ctime(LogonTime_decimal)%0A%7C%20fillnull%20value%3D%22N%2FA%22%20UserPrincipal%0A%7C%20table%20ComputerName%20Version%20LogonTime_decimal%20UserName%20UserPrincipal%20LogonServer%20LogonDomain%20AuthenticationPackage%0A%7C%20rename%20ComputerName%20AS%20Endpoint%2C%20Version%20AS%20%22Operating%20System%22%2C%20LogonTime_decimal%20AS%20%22Logon%20Time%22%2C%20UserName%20AS%20User%2C%20UserPrincipal%20AS%20Principal%2C%20LogonServer%20AS%20%22Logon%20Server%22%2C%20LogonDomain%20AS%20Domain%2C%20AuthenticationPackage%20AS%20%22Auth%20Package%22%20&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600166081.17970">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# UAC Elevation Events

> View UAC elevation attempts for administrative operations. 

    index=main sourcetype="UACExeElevation*"
    | iplocation aip | lookup aid_master aid OUTPUT Version
    | stats count BY ComputerName, Region, Version, UACCommandLineToValidate     

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%20sourcetype%3D%22UACExeElevation*%22%0A%7C%20iplocation%20aip%20%7C%20lookup%20aid_master%20aid%20OUTPUT%20Version%0A%7C%20stats%20count%20BY%20ComputerName%2C%20Region%2C%20Version%2C%20UACCommandLineToValidate&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.visualizations.type=mapping&display.visualizations.mapping.type=choropleth&sid=1600166535.17986">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Windows Authentication Events by Type

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
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>