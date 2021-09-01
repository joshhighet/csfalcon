# DNS Requests sorted by Top-Level Domain

> Outputs a table containing the TLD, FQDN's from DNS data, by count of unique domains.

    event_simpleName=DnsRequest 
    | rex field=DomainName "[@\.](?<domain>\w+\.\w+)$"
    | stats count(domain) AS "Hits" dc(DomainName) values(DomainName) by domain
    | rename domain AS "TLD", dc(DomainName) AS "Unique Domains", values(DomainName) AS "FQDN"
    | sort - Hits

<a href="https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/search?q=search%20event_simpleName%3DDnsRequest%20%0A%7C%20rex%20field%3DDomainName%20%22%5B%40%5C.%5D(%3F%3Cdomain%3E%5Cw%2B%5C.%5Cw%2B)%24%22%0A%7C%20stats%20count(domain)%20AS%20%22Hits%22%20dc(DomainName)%20values(DomainName)%20by%20domain%0A%7C%20rename%20domain%20AS%20%22TLD%22%2C%20dc(DomainName)%20AS%20%22Unique%20Domains%22%2C%20values(DomainName)%20AS%20%22FQDN%22%0A%7C%20sort%20-%20Hits%20&display.page.search.mode=verbose&dispatch.sample_ratio=1&earliest=-7d%40h&latest=now&display.page.search.tab=statistics&display.general.type=statistics&sid=1600165947.17967">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# Dynamic DNS Providers

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

# DNS IOC Hunt

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
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

# DNS Over HTTPS Usage

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
