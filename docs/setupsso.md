## Azure Active Directory

Eliminate operational overhead whilst streamlining access for internal stakeholders with a single set of credentials.

Visual learner? [Follow this recording](https://thetacyber.blob.core.windows.net/public/cs/setup-sso.MP4) as we go through the steps below.

---

1. Visit the [Azure AD Enterprise Applications Pane](https://portal.azure.com/#blade/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/AllApps/menuId/)

2. Select `New Application`

3. Select `Create your own application`

4. In the name field, enter `CrowdStrike Falcon`

5. When asked what you looking to do with the application, select
`Integrate any other application you don't find in the gallery`

6. Create the Application _This may take a few moments_

7. Once created you will be taken to the `Overview` pane for the application. Select the `Properties` pane

6. Download the [CrowdStrike Icon](https://cyberdisk.thetasystems.co.nz/public/icons/crowdstrike.png) and upload this to the `Logo` section. _This will be presented to users from the SSO dashboard_

7. Navigate to the `Single Sign On` pane and select `SAML`

8. Under `Basic SAML Configuration [1]` select `Edit`

9. In the Identifier (Entity ID) field enter `https://falcon.crowdstrike.com/saml/metadata`

10. In the Reply URL Assertion Consumer Service URL) field enter
`https://falcon.crowdstrike.com/saml/acs`

11. In the Sign On URL field enter `https://falcon.crowdstrike.com/login/sso`

12. Select `Save Basic SAML Configuration`

13. Under `SAML Signing Certificate [3]` select `Edit`

14. Modify the `Notification Email` to an applicable address for the internal service owner. _When the active signing certificate is near the expiration, a notification is sent to this address._ 

14. Note down the URL in the `App Federation Metadata Url` field

15. Under `SAML Signing Certificate` select `Download the Federation Metadata XML`

16. Provide the `SAML Signing Certificate` and `App Federation Metadata URL` to CrowdStrike in a [Support Request](mailto:support@crowdstrike.com?subject=Request%20for%20SSO%20Integration) titled `Request for SSO Integration`

17. Once SSO with CrowdStrike has been configured, a further request to support is required to take the tenant out of `Onboarding Mode`. This will require all authentication to be granted through Azure AD and local accounts will cease t◊o function.

For issues and troubleshooting, See [CrowdStrike's SSO Guide](https://falcon.crowdstrike.com/support/documentation/33/single-sign-on-sso-for-falcon)
