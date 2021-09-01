# View Remote Desktop Protocol Activity

> To exclude or select a given host, add `ComputerName!=MYHOSTNAME` to the first line of this search.

> _A table is returned with the hostname, username and unique count of connections._

    event_simpleName=UserLogon LogonType_decimal=10
    | stats values(UserName) dc(UserName) AS "User Count" count(UserName) AS "Logon Count" by ComputerName
    | rename ComputerName AS Hostname, values(UserName) AS User
    | sort - "Logon Count"

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20event_simpleName%3DUserLogon%20LogonType_decimal%3D10%0A%20%20%20%20%7C%20stats%20values(UserName)%20dc(UserName)%20AS%20%22User%20Count%22%20count(UserName)%20AS%20%22Logon%20Count%22%20by%20ComputerName%0A%20%20%20%20%7C%20rename%20ComputerName%20AS%20Hostname%2C%20values(UserName)%20AS%20User%0A%20%20%20%20%7C%20sort%20-%20%22Logon%20Count%22&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-60m%40m&latest=now&sid=1605745355.11334&display.page.search.tab=statistics&display.general.type=statistics">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Network Activity on Hosts - Listening Ports

> The `LPort` field sets the service you are investigating. In this example, we are looking for hosts that have recently started listening for remote desktop protocol, over port 3389 within the last 24 hours.

> _A table is returned with the hostname, operating system, machine domain, sitename & ou from active directory._

    index=main source=main event_simpleName=NetworkListenIP4 LPort=3389
    | dedup aid
    | lookup aid_master aid OUTPUT Version MachineDomain OU SiteName
    | table ComputerName Version MachineDomain OU SiteName 

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20index%3Dmain%20source%3Dmain%20event_simpleName%3DNetworkListenIP4%20LPort%3D3389%0A%20%20%20%20%7C%20dedup%20aid%0A%20%20%20%20%7C%20lookup%20aid_master%20aid%20OUTPUT%20Version%20MachineDomain%20OU%20SiteName%0A%20%20%20%20%7C%20table%20ComputerName%20Version%20MachineDomain%20OU%20SiteName&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-24h%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1605745761.11340">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>