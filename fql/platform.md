# Indicators of Interest

> CrowdStrike Detection Metadata

    index=main source=main
    | table DetectDescription,sourcetype
    | sort DetectDescription
    | search NOT (DetectDescription="Experimental detection.")
    | stats values(sourcetype) by DetectDescription     

<a href="https://falcon.crowdstrike.com/eam/en-US/app/eam2/search?q=search%20index%3Dmain%20source%3Dmain%0A%7C%20table%20DetectDescription%2Csourcetype%0A%7C%20sort%20DetectDescription%0A%7C%20search%20NOT%20(DetectDescription%3D%22Experimental%20detection.%22)%0A%7C%20stats%20values(sourcetype)%20by%20DetectDescription&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&display.visualizations.type=mapping&display.visualizations.mapping.type=choropleth&sid=1600166460.17983">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# RTR Audit Records

> _This will return a list of RTR sessions by the initiating user, hostname with a unique session count._

    source=PlatformEvents | spath EventType | search EventType=Event_ExternalApiEvent 
    | spath ExternalApiType | search ExternalApiType=Event_RemoteResponseSessionStartEvent
    | stats Count by HostnameField, UserName | table Count HostnameField, UserName
    | rename Count AS "RTR Sessions",HostnameField AS Hostname,UserName AS Analyst

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20source%3DPlatformEvents%20%7C%20spath%20EventType%20%7C%20search%20EventType%3DEvent_ExternalApiEvent%20%0A%7C%20spath%20ExternalApiType%20%7C%20search%20ExternalApiType%3DEvent_RemoteResponseSessionStartEvent%0A%7C%20stats%20Count%20by%20HostnameField%2C%20UserName%20%7C%20table%20Count%20HostnameField%2C%20UserName%0A%7C%20rename%20Count%20AS%20%22RTR%20Sessions%22%2CHostnameField%20AS%20Hostname%2CUserName%20AS%20Analyst&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-3d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600161458.17855">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Falcon User Account Creation

> Dependant on your CrowdStrike Configuration, This search may need to be modified to accomodate for MSSP and switching account setups.

    index=json EventType=Event_ExternalApiEvent OperationName=CreateApiClient OR OperationName=createUser Success=true
    | table OperationName,ServiceName,UserId,AuditKeyValues{}.ValueString
    | rename OperationName as Action,ServiceName as Service,UserId as User,AuditKeyValues{}.ValueString as "New User ID"

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20index%3Djson%20EventType%3DEvent_ExternalApiEvent%20OperationName%3DCreateApiClient%20OR%20OperationName%3DcreateUser%20Success%3Dtrue%0A%7C%20table%20OperationName%2CServiceName%2CUserId%2CAuditKeyValues%7B%7D.ValueString%0A%7C%20rename%20OperationName%20as%20Action%2CServiceName%20as%20Service%2CUserId%20as%20User%2CAuditKeyValues%7B%7D.ValueString%20as%20%22New%20User%20ID%22&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-30d%40d&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600161173.15377">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Logons to the Falcon UI 

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
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>