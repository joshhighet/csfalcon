# Executable Activity Outside of Primary HDD Partition

> :warning: **under construction 🚧**

> This search intends to discover executables running from removable media - more work required to identify with HarddiskVolume*

    event_simpleName=ProcessRollup* ImageFileName!="\Device\HarddiskVolume1\*"
    | table _time ComputerName aip FileName CommandLine
    | rename ComputerName as Hostname,aip as "External IP",FileName as File,CommandLine as Command     

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20event_simpleName%3DProcessRollup*%20ImageFileName!%3D%22%5CDevice%5CHarddiskVolume1%5C*%22%0A%7C%20table%20_time%20ComputerName%20aip%20FileName%20CommandLine%0A%7C%20rename%20ComputerName%20as%20Hostname%2Caip%20as%20%22External%20IP%22%2CFileName%20as%20File%2CCommandLine%20as%20Command&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600165731.17950">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Microsoft Office Password Hunting

> An excercise in hygiene.

    index=main ImageFileName="*Office*" event_simpleName=*ProcessRollup2 
    | search password 
    | table  ComputerName SourceFileName ImageFileName CommandLine, UserName  

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20index%3Dmain%20ImageFileName%3D%22*Office*%22%20event_simpleName%3D*ProcessRollup2%20%0A%7C%20%20search%20password%20%0A%7C%20table%20%20ComputerName%20SourceFileName%20ImageFileName%20CommandLine%2C%20UserName%20&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600165879.17961">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>


# SMB File Share Usage & Statistics

> View SMB actions by client, server, fileshare name and count of operations

    index=main sourcetype="SmbClientShareOpenedEtwV1-v02"
    | rename event_simpleName AS Action,ClientComputerName AS Server,ComputerName AS Client,SmbShareName AS "Share Name"
    | replace SmbClientShareOpenedEtw WITH "SMB Share Opened" IN Action
    | search NOT (Server=localhost)
    | stats count by Action,Client,Server,"Share Name"

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%20sourcetype%3D%22SmbClientShareOpenedEtwV1-v02%22%0A%7C%20rename%20event_simpleName%20AS%20Action%2CClientComputerName%20AS%20Server%2CComputerName%20AS%20Client%2CSmbShareName%20AS%20%22Share%20Name%22%0A%7C%20replace%20SmbClientShareOpenedEtw%20WITH%20%22SMB%20Share%20Opened%22%20IN%20Action%0A%7C%20search%20NOT%20(Server%3Dlocalhost)%0A%7C%20stats%20count%20by%20Action%2CClient%2CServer%2C%22Share%20Name%22&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.visualizations.type=mapping&display.visualizations.mapping.type=choropleth&sid=1600166379.17978">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Running Scripts Insights - Decoded Powershell, Bash & Zsh

> Review & hunt decoded scripts. Reccomend building an exclusion set to cater to each unique environment.

    index=main  sourcetype="ScriptControlDetectInfoV4-v02" OR sourcetype="CommandHistoryV2-v02" 
    | search NOT (ScriptContent=*LogicMonitor* OR ScriptContent="*PublicKeyToken=31bf3856ad364e35*")
    | replace CommandHistory WITH ScriptContent IN "CommandHistoryV2-v02"
    | dedup ScriptContent 
    | iplocation aip
    | table DetectDescription,ComputerName,City,ScriptContent

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%20%20sourcetype%3D%22ScriptControlDetectInfoV4-v02%22%20OR%20sourcetype%3D%22CommandHistoryV2-v02%22%20%0A%7C%20search%20NOT%20(ScriptContent%3D*LogicMonitor*%20OR%20ScriptContent%3D%22*PublicKeyToken%3D31bf3856ad364e35*%22)%0A%7C%20replace%20CommandHistory%20WITH%20ScriptContent%20IN%20%22CommandHistoryV2-v02%22%0A%7C%20dedup%20ScriptContent%20%0A%7C%20iplocation%20aip%0A%7C%20table%20DetectDescription%2CComputerName%2CCity%2CScriptContent%20&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.visualizations.type=mapping&display.visualizations.mapping.type=choropleth&sid=1600166419.17981">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Executables Taking Screenshots 

> Teams has been excluded and other video-conferencing solutions may need to be added to minimise the noise
    
    index=main sourcetype="ScreenshotTakenEtwV2-v02" FileName!="Teams.exe"
    |  stats count by ComputerName,UserName,FileName | rename count as Screenshots     

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%20sourcetype%3D%22ScreenshotTakenEtwV2-v02%22%20FileName!%3D%22Teams.exe%22%0A%7C%20%20stats%20count%20by%20ComputerName%2CUserName%2CFileName%20%7C%20rename%20count%20as%20Screenshots%20&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.visualizations.type=mapping&display.visualizations.mapping.type=choropleth&sid=1600166603.17992">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>
