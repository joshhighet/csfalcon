# List All Sensor IP Addresses

> The task of obtaining a list of all external IP addresses associated to managed devices is more commonly completed through the Falcon API but can also be done through the UI with the below search.

    index=main source=main | dedup "Agent IP" 
    | table "Agent IP" | rename "Agent IP" as "External Address"

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20index%3Dmain%20source%3Dmain%20%7C%20dedup%20%22Agent%20IP%22%20%7C%20table%20%22Agent%20IP%22%20%7C%20rename%20%22Agent%20IP%22%20as%20%22External%20Address%22&sid=1600161468.17856&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-15m&latest=now&display.page.search.tab=statistics&display.general.type=statistics">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Windows Build - Fleet Summary

> Generate a report of the various Windows Builds within an environment

    index=main event_platform=win ComputerName=*
    | lookup local=true aid_master aid OUTPUT Version
    | stats dc(event_simpleName) as eventCount latest(BuildNumber_decimal) as buildNumber latest(SubBuildNumber_decimal) as subBuildNumber by aid, ComputerName
    | rename ComputerName as hosts
    | stats count(hosts) by buildNumber

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?earliest=-7d%40h&latest=now&q=search%20index%3Dmain%20event_platform%3Dwin%20ComputerName%3D*%0A%7C%20lookup%20local%3Dtrue%20aid_master%20aid%20OUTPUT%20Version%0A%7C%20stats%20dc(event_simpleName)%20as%20eventCount%20latest(BuildNumber_decimal)%20as%20buildNumber%20latest(SubBuildNumber_decimal)%20as%20subBuildNumber%20by%20aid%2C%20ComputerName%0A%7C%20rename%20ComputerName%20as%20hosts%0A%7C%20stats%20count(hosts)%20by%20buildNumber&display.page.search.mode=fast&dispatch.sample_ratio=1&display.general.type=visualizations&display.page.search.tab=visualizations&display.visualizations.charting.chart=bar&sid=1630446275.8422">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Remote Device Insights

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
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# View Devices on a Map

> After running this search head to the `Visualisations` tab and select `Cloropleth`  to view hthe coordinates represented

    index=main
    | table aip
    | iplocation aip
    | stats count by Country
    | geom geo_countries allFeatures=True featureIdField=Country  

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%0A%7C%20table%20aip%0A%7C%20iplocation%20aip%0A%7C%20stats%20count%20by%20Country%0A%7C%20geom%20geo_countries%20allFeatures%3DTrue%20featureIdField%3DCountry%20&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=visualizations&display.general.type=visualizations&sid=1600166281.17975&display.visualizations.type=mapping&display.visualizations.mapping.type=choropleth">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Device Overview by Type

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
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Unencrypted C Drives - BitLocker Review

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
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>