
![](https://avatars0.githubusercontent.com/u/2897191?s=90&v=4) ![](https://avatars0.githubusercontent.com/u/2446477?s=70&v=4)

<!--
this resource would not have been made possible 
without the help of the crowdstrike community on reddit 
https://www.reddit.com/r/crowdstrike
-->

# SPL/FQL Threat Hunting Reference Guide

A number of searches in Falcon Query Language (FQL), intended for use when hunting within Crowdstrike Falcon's Threat Graph - served by [docsify](https://docsify.js.org)

These searches may not represent all data available within your tenant and searches should be reviewed before they're operationalised.

Searches may create strange values for time fields due to Splunk transforms - this can be resolved with `convert ctime(timestamp/1000)`

> :warning: You'll need to login to Crowdstrike before using any of the direct-search buttons.

CrowdStrike Community Work

* [Reddit Community](https://www.reddit.com/r/crowdstrike/)
* [Crowdstrike Splunk Threat Hunting Searches - rmccurdy](https://docs.google.com/spreadsheets/d/1RTcZsRbDsjxwmKpe3FIvSKUjBk5pR2Dlzj71QTnxAK0/edit#gid=0)
* [CrowdStrike Falcon Queries - pe3zx](https://github.com/pe3zx/crowdstrike-falcon-queries)

https://user-images.githubusercontent.com/17993143/142487329-0c8635cd-ba6b-4b37-8999-0cf8ddd4dbd2.mp4

---

<!-- [template]

## SearchTitle

> SearchNotes

```rb
SPL-FQL-Query
```

<a href="FALCON-URL-HERE">
<img border="0" alt="thetacyber-csfalcon-fqlsearch" src="https://csfalcon.thetadev.services/assets/search.png" height="40"></a>

-->

[csfalcon.thetadev.services](https://csfalcon.thetadev.services)
