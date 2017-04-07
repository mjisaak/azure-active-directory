# Azure-Active-Directory
This readme provides some information about Azure Active Directory for developers. 

## Choosing an API
There are many ways to programmatically manage the Azure Active Directory. 
### PowerShell
Within PowerShell there is the [MSOnline](https://docs.microsoft.com/en-us/powershell/msonline/) module which was the *first* available AAD PowerShell module.
Then there is the [AzureAD](https://docs.microsoft.com/en-us/powershell/azuread/v2/azureactivedirectory) module which basically is  *version 2* of the AAD modules. And finally there is the [AzureRM.Resources](https://www.powershellgallery.com/packages/AzureRM.Resources) module which also contains some cmdlets to manage an AAD. 

Both, the *AzureAD* and the *AzureRM.Resources* module are using the **Graph API** (REST) whereas the *MSOnline* module is using a SOAP based **legacy** API (https://provisioningapi.microsoftonline.com/provisioningwebservice.svc).

If you have to create an AAD application, you **shouldn't** use the```New-MsolServicePrincipal``` (*MSonline*) nor the ```New-AzureRmADServicePrincipal```(*AzureRm.Resources*) cmdlet. 
Both of these cmdlets will create some kind of applications in the background but:
- The ```New-MsolServicePrincipal``` creates a *hidden application* and *hidden service principal* (you won't be able to see them in neither the old nor the new Portal), similar to Microsoft internal apps (it also sets ```servicePrincipalType=Legacy```)
- The ```New-AzureRmADServicePrincipal``` creates an application for you and then creates the service principal. The application is visible in the Portal, but the service principal is not. This is because the principal is missing the ```WindowsAzureActiveDirectoryIntegratedApp``` tag. 

However, if you already created an AAD application using the ```New-AzureRmADServicePrincipal``` cmdlet and you want to see the service principal in the Portal (Enterprise Application list), you can fix it by setting the necessary tag:
```powershell
New-AzureADServicePrincipal -Tags @("WindowsAzureActiveDirectoryIntegratedApp") -AppId <APPID>
```
Fortunately, the ```New-AzureADServicePrincipal``` does not allow you to create it without providing an application id. 

If you have to choose a module you should know that MSOnline will probably get [deprecated soon](https://docs.microsoft.com/en-us/powershell/msonline/). 
### REST
To make the confusion complete, there are also two different REST APIs available both known as Microsoft **Graph**.
- graph.windows.net (Azure AD Graph API) 
- graph.microsoft.com (Microsoft Graph - a unifed API - *"One endpoint to rule them all"*)

A good starting point for the Azure AD Graph API is the [quickstart site](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-graph-api-quickstart), the [list of common queries](https://msdn.microsoft.com/Library/Azure/Ad/Graph/howto/azure-ad-graph-api-supported-queries-filters-and-paging-options#CommonQueries) and of course the [Graph Explorer](https://graphexplorer.cloudapp.net/). Both APIs supports Odata but the Azure AD Graph API doesn't support `$select` out of the box:

> The ability to use the $select query option to define a projection in a data service query is disabled. To enable this functionality, > set the DataServiceConfiguration. AcceptProjectionRequests property to true.

***Tip:***
> Use the Odata `$filter` expression to prefilter resources on the *server*. For example, get a user by its UPN:
> https://graph.windows.net/mytenant.onmicrosoft.com/users?$filter=userPrincipalName eq 'myuser@mytenant.onmicrosoft.com'&api-version=1.6


**Note:** In the portal, the application represents the actual application templates whereas the enterprise applications represent the service principals:

![AAD service principal and application template](https://github.com/mjisaak/azure-active-directory/blob/master/resources/aad-applicationandsp.png)

## Disable user browsing
In Azure AD, Users and groups are created in a flat structure without OU and GPO. By default, every user can browse other users and groups. Fortunately there is a flag that you can set using the MSOnline module to disable user browsing for "normal" users:

```powershell
Connect-MsolService
Set-MsolCompanySettings -UsersPermissionToReadOtherUsersEnabled $false
```

***Tip:***
> For the Azure German Cloud (MCD) you won't be able to connect with the default `Connect-MsolService` cmdlet. There is a MSI ( [AdministrationConfig-V1.1.166.0-GA.msi](http://connect.microsoft.com/site1164/Downloads/DownloadDetails.aspx?DownloadID=59185)) which extends the cmdlet with a `-AzureEnvironment` parameter. After you installed the MSI you can authenticate against MSOnline using `Connect-MsolService -AzureEnvironment AzureGermanyCloud`


# Well known AppIds
If you want to create an application using the Graph API, you have to specify the `requiredResourceAccess`. To retrieve the `resourceAppId` for the desired resource, you can use the `Get-AzureADServicePrincipal` cmdlet:
``` powershell
Get-AzureADServicePrincipal | Where-Object AppId -Match '\w{8}-\w{4}-\w{4}-c000'

ObjectId                             AppId                                DisplayName                   
--------                             -----                                -----------                   
175235f9-e4a8-47c3-8b8c-8650e46b5e17 0000000f-0000-0000-c000-000000000000 Microsoft.Azure.GraphExplorer 
897dea0d-ae6f-4958-865f-43fa66a3a9ff 00000013-0000-0000-c000-000000000000 Azure Classic Portal          
9895cd98-d381-4392-bec5-10f7a901eb97 00000014-0000-0000-c000-000000000000 Microsoft.Azure.SyncFabric    
99b1ca61-d3ae-4ad9-8219-fabd826ce248 00000003-0000-0000-c000-000000000000 Microsoft Graph               
a019dc0d-a15c-4add-88df-d3b677bf8144 00000002-0000-0000-c000-000000000000 Windows Azure Active Directory
d74b30d7-435c-4b6c-89ea-ec5b744ec9ca 00000001-0000-0000-c000-000000000000 Azure ESTS Service            
f5e8351e-a68a-4b24-b2b5-ef88d5a88061 0000000c-0000-0000-c000-000000000000 Microsoft App Access Panel   
```
Using the desired `ObjectId` above you can retrieve all **Oauth2Permissions** (delegated, type=Scope) using:
```powershell
Get-AzureAdServicePrincipal -ObjectId 99b1ca61-d3ae-4ad9-8219-fabd826ce248 | 
    Select-Object -expand Oauth2Permissions | 
    Select-Object Id, AdminConsentDisplayName | 
    Sort-Object Id
    
Id                                   AdminConsentDisplayName                                          
--                                   -----------------------                                          
024d486e-b451-40bb-833d-3e66d98c5c73 Read and write access to user mail                               
02e97553-ed7b-43d0-ab3c-f8bace0d040c Read all usage reports                                           
06da0dbc-49e2-44d2-8312-53f166ab848a Read directory data                                              
0e263e50-5827-48a4-b97c-d940288653c7 Access directory as the signed in user                           
10465720-29dd-4523-a11a-6a75c743c9d9 Read user files                                                  
12466101-c9b8-439a-8589-dd09ee67e8e9 Read and write user and shared calendars                         
14dad69e-099b-42c9-810b-d002981feec1 View users' basic profile                                        
17dde5bd-8c17-420f-a486-969730c1b827 Read and write files that the user selects (preview)             
1ec239c2-d7c9-4623-a91a-a9775856bb36 Have full access to user calendars                               
204e0828-b5ca-4ad8-b9f3-f32a958e7cc4 Read and write all users' full profiles                          
205e70e5-aba6-4c52-a976-6d2d46c48043 Read items in all site collections                               
2219042f-cab5-40cc-b0d2-16b1540b4c5f Create, read, update and delete user tasks and projects (preview)
242b9d9e-ed24-4d09-9a52-f43769beb9d4 Read user and shared contacts                                    
2b9c4092-424d-4249-948d-b43879977640 Read user and shared calendars                                   
371361e4-b9e2-4a3f-8315-2a301a3b0a3d Read user notebooks (preview)                                    
37f7f235-527c-4136-accd-4a02d197296e Sign users in                                                    
465a38f9-76ea-45b9-9f34-9e8b0d4b0b42 Read user calendars                                              
4e46008b-f24c-477d-8fff-7bb4ec7aafe0 Read and write all groups                                        
5447fe39-cb82-4c1a-b977-520e67e724eb Read files that the user selects (preview)                       
570282fd-fa5c-430d-a7fd-fc8dc98a9dca Read user mail                                                   
5c28f0bf-8a70-41f1-8ab2-9032436ddb65 Have full access to user files                                   
5df07973-7d5d-46ed-9847-1271055cbd51 Read and write user and shared mail                              
5f8c59db-677d-491f-a6b8-5f174b11ec1d Read all groups                                                  
615e26af-c38a-4150-ae3e-c3b0d4cb1d6a Read and write user notebooks (preview)                          
64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0 View users' email address                                        
64ac0503-b4fa-45d9-b544-71a463f05da0 Read and write notebooks that the user can access (preview)      
7427e0e9-2fba-42fe-b0c0-848c9e6a8182 Access user's data anytime                                       
7b9103a5-4610-446b-9670-80643382c1fa Read user and shared mail                                        
8019c312-3263-48e6-825e-2b833497195b Have full access to the application's folder (preview)           
818c620a-27a9-40bd-a6a5-d96f7d610b4b Read and write user mailbox settings (preview)                   
863451e7-0667-486c-a5d6-d135439485f0 Have full access to all files user can access                    
88d21fd4-8e5a-4c32-b5e2-4a1c95f34f72 Read user and shared tasks                                       
89fe6a52-be36-487e-b7d8-d061c450a026 Edit or delete items in all site collections                     
8f6a01e7-0391-4ee5-aa22-a3af122cef27 Read identity risk event information                             
9d822255-d64d-4b7a-afdb-833b9a97ed02 Create pages in user notebooks (preview)                         
a154be20-db9c-4678-8ab7-66f6cc099a59 Read all users' full profiles                                    
a367ab51-6b49-43bf-a716-a1fb06d2a174 Send mail on behalf of others                                    
afb6c84b-06be-49af-80bb-8f3f77004eab Read and write user and shared contacts                          
b340eb25-3456-403f-be2f-af7a0d370277 Read all users' basic profiles                                   
b4e74841-8e56-480b-be8b-910348b18b4c Read and write access to user profile                            
ba47897c-39ec-4d83-8086-ee8256fa737d Read users' relevant people lists (preview)                      
c5366453-9fb0-48a5-a156-24f0c49a4b84 Read and write directory data                                    
c5ddf11b-c114-4886-8558-8a4e557cd52b Read and write user and shared tasks                             
d56682ec-c09e-4743-aaf4-1a3aac4caa21 Have full access to user contacts                                
df85f4d6-205c-4ac5-a5ea-6bf408dba283 Read all files that user can access                              
dfabfca6-ee36-4db2-8208-7a28381419b3 Read all notebooks that the user can access (preview)            
e1fe6dd8-ba31-4d61-89e7-88639da4683d Sign in and read user profile                                    
e383f46e-2787-4529-855e-0e479a3ffac0 Send mail as a user                                              
ed68249d-017c-4df5-9113-e684c7f8760b Limited notebook access (preview)                                
f45671fb-e0fe-4b4b-be20-3d3ce43f1bcb Read user tasks                                                  
ff74d97f-43af-4b68-9f2a-b77ee6968c5d Read user contacts
```
To get the **appRoles** (application permissions, type=Role):
```powershell
Get-AzureAdServicePrincipal -ObjectId 99b1ca61-d3ae-4ad9-8219-fabd826ce248 |
  Select-Object -expand AppRoles | 
  Select-Object Id, DisplayName | 
  Sort-Object Id
  
Id                                   DisplayName                                           
--                                   -----------                                           
01d4889c-1287-42c6-ac1f-5d1e02578ef6 Read files in all site collections (preview)          
089fe4d0-434a-44c5-8827-41ba8a0b17f5 Read contacts in all mailboxes                        
1138cb37-bd11-4084-a2b7-9f71582aeddb Read and write devices                                
19dbc75e-c2e2-444c-a770-ec69d8559fc7 Read and write directory data                         
230c1aed-a721-4c5d-9cb4-a90514e508ef Read all usage reports                                
5b567255-7703-4780-807c-7be8301ae99b Read all groups                                       
62a82d76-70ea-41e2-9197-370581804d09 Read and write all groups                             
658aa5d8-239f-45c4-aa12-864f4fc7e490 Read all hidden memberships                           
6918b873-d17a-4dc1-b314-35f528134491 Read and write contacts in all mailboxes              
6931bccd-447a-43d1-b442-00a195474933 Read and write all user mailbox settings (preview)    
6e472fd1-ad78-48da-a0f0-97ab2c6b769e Read all identity risk event information              
741f803b-c850-494e-b5df-cde7c675a1ca Read and write all users' full profiles               
75359482-378d-4052-8f01-80520e7db3cd Read and write files in all site collections (preview)
798ee544-9d2d-430c-a058-570e29e34338 Read calendars in all mailboxes                       
7ab1d382-f21e-4acd-a863-ba3e13f7da61 Read directory data                                   
810c84a8-4a9e-49e6-bf7d-12d183f40d01 Read mail in all mailboxes                            
b633e1c5-b582-4048-a93e-9f11b44c7e96 Send mail as any user                                 
df021288-bdef-4463-88db-98f22de89214 Read all users' full profiles                         
e2a3a72e-5f79-4c64-b1b1-878b674786c9 Read and write mail in all mailboxes                  
ef54d2bf-783f-4e0f-bca1-3210c0444d99 Read and write calendars in all mailboxes
```

# Authentication: Secured native app -> Secured web API
Based on this [article](https://github.com/mjisaak/active-directory-dotnet-webapi-onbehalfof) the following snippets shows how to secure a .net core native application and call a secured asp.net core web API using the obtained token:

Example values:
```
WebAPI App Id   e8114585-7fba-47bc-bc4f-5c2a4a52c2c1
Native App Id   acc8d1ec-9f89-4b01-9134-58c54d50cb9a
Tenant          mytenant.onmicrosoft.com
```


## Web API:
Startup.cs Configure:
```csharp
app.UseJwtBearerAuthentication(new JwtBearerOptions
{
    Authority = @"https://login.microsoftonline.com/" + "mytenant.onmicrosoft.com",
    Audience = "e8114585-7fba-47bc-bc4f-5c2a4a52c2c1" // WebAPI AppId (own)
});
```
## Native application
E. g. console.
```csharp
static void Main(string[] args)
{
    var authority = @"https://login.microsoftonline.com/mytenant.onmicrosoft.com";
    var resource = "e8114585-7fba-47bc-bc4f-5c2a4a52c2c1"; // WebAPI AppId
    var clientId = "acc8d1ec-9f89-4b01-9134-58c54d50cb9a";  // Native AppId (own)
    var redirectUri = @"https://www.mytenant.de";

    var authContext = new AuthenticationContext(authority);

    var authenticationResult = authContext.AcquireTokenAsync(
        resource, 
        clientId, 
        new Uri(redirectUri), 
        new PlatformParameters(PromptBehavior.Auto)).GetAwaiter().GetResult();

    var httpClient = new HttpClient();
    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authenticationResult.AccessToken);
    HttpResponseMessage response2 = httpClient.GetAsync(@"http://localhost:65098/api/" + "values/1").GetAwaiter().GetResult() ;
}
```

# Increase AccessToken Lifetime
Based on [this article](https://docs.microsoft.com/en-us/azure/active-directory/active-directory-configurable-token-lifetimes).
```powershell
Import-Module AzureADPreview -Force
Connect-AzureAd

New-AzureADPolicy `
-Definition @('{"TokenLifetimePolicy":{"Version":1, "AccessTokenLifetime":"23:00:00"}}') `
-DisplayName "IncreasedAccessTokenLT" `
-IsOrganizationDefault $true `
-Type "TokenLifetimePolicy"

# verify:
Get-AzureADPolicy
```

# Retrieve Access Token using the Authorization Code Flow
PowerShell snippet to obtain an AAD access token, id token and refresh token using the [OAuth 2.0 authorization code flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code):

```powershell
function Get-AuthorizationCode
{
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Tenant,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$ClientId,

        [Parameter(Mandatory=$true, Position=2)]
        [string]$RedirectUri
    )
    $authorizationRequest = "https://login.microsoftonline.com/$Tenant/oauth2/authorize?response_type=code&client_id=$ClientId&redirect_uri=$RedirectUri"
 
    $internetExplorer = New-Object -ComObject InternetExplorer.Application
    $internetExplorer.visible = $true
    $internetExplorer.navigate2($authorizationRequest)

    # workaround: If the user is already sign in we have to refresh the page in order to get redirected.
    do
    {
        Start-Sleep -Milliseconds 100       
    } 
    until($internetExplorer.LocationURL)
    $internetExplorer.Refresh()

    do
    {
        Start-Sleep -Seconds 1
    } 
    until($internetExplorer.LocationURL -match 'code=([^&]+)')
    $internetExplorer.Quit()
    $matches[1]
}


function Get-AccessToken
{
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Tenant,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$ClientId,

        [Parameter(Mandatory=$true, Position=2)]
        [string]$ClientSecret,

        [Parameter(Mandatory=$true, Position=3)]
        [string]$RedirectUri,

        [Parameter(Mandatory=$true, Position=4)]
        [string]$AuthorizationCode      
    )

    Add-Type -AssemblyName System.Web
    $encodedReplyUrl = [System.Web.HttpUtility]::UrlEncode($RedirectUri)
    $encodedClientSecret = [System.Web.HttpUtility]::UrlEncode($ClientSecret)

    $invokeParameter = @{
            Body = "grant_type=authorization_code&client_id=$ClientId&code=$AuthorizationCode&redirect_uri=$encodedReplyUrl&client_secret=$encodedClientSecret&resource=$ClientId"
            Uri = "https://login.microsoftonline.com/$Tenant/oauth2/token"
            ContentType = "application/x-www-form-urlencoded"
            Method = 'Post'
        }
    Invoke-RestMethod @invokeParameter
}
```
usage:
```powershell
$authCode = Get-AuthorizationCode -Tenant '<tenant>' -ClientId '<client id>'  -RedirectUri '<redirect uri>'
$token = Get-AccessToken -Tenant '<tenant>' -ClientId '<client id>' -ClientSecret '<client secret>' -RedirectUri '<redirect uri>' -AuthorizationCode $authCode
```

Receive an Access Token using the resource owner password flow


