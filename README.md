# Azure-Active-Directory

There are many ways to programmatically manage the Azure Active Directory. 

Within PowerShell there is the [MSOnline](https://docs.microsoft.com/en-us/powershell/msonline/) module which was the *first* available AAD PowerShell module.
Then there is the [AzureAD](https://docs.microsoft.com/en-us/powershell/azuread/v2/azureactivedirectory) module which basically is  *version 2* of the AAD modules. And finally there is the [AzureRM.Resources](https://www.powershellgallery.com/packages/AzureRM.Resources) module which also contains some cmdlets to manage an AAD. 

Both, the *AzureAD* and the *AzureRM.Resources* module are using the **Graph API** (REST) whereas the *MSOnline* module is using a SOAP based **legacy** API (https://provisioningapi.microsoftonline.com/provisioningwebservice.svc).

If you have to choose a module you should know that MSOnline will probably get [deprecated soon](https://docs.microsoft.com/en-us/powershell/msonline/). 

To make the confusion complete, there are two different REST APIs available both known as Microsoft Graph API.
- graph.windows.net 
- graph.microsoft.com

Recommendations:
If you have to create an AAD application and service principal you shouldn't use the MSonline (New-MsolServicePrincipal) nor AzureRm.Resources (New-AzureRmADServicePrincipal). Both of these cmdlets will create some kind of applications in the background but:
The New-MsolServicePrincipal creates a hidden application and hidden service principal (you won't see them in neither the old nor the new Portal), similar to Microsoft internal apps (it also sets servicePrincipalType=Legacy)
The New-AzureRmADServicePrincipal creates an application for you and then creates the service principal. The application is visible in the Portal, but the service principal is not. This is because the SP is missing the "WindowsAzureActiveDirectoryIntegratedApp" tag. 
However, if you already created an AAD application using the New-AzureRmADServicePrincipal cmdlet and you want to see the SP in the Portal (Enterprise Application list), you can fix it by setting the necessary tag:
New-AzureADServicePrincipal -Tags @("WindowsAzureActiveDirectoryIntegratedApp") -AppId <APPID>
Fortunately, the New-AzureADServicePrincipal does not allow you to create it without providing an application id. 


Note: In the portal, the application represents the actual application templates whereas the enterprise applications represent the service principals.
