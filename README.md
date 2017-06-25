# Python CSP module and CSP CLI application

This repository contains cspcli.py, a python module with functions to interact with the CSP REST API.

The module contains as well a shell application, that can be used in order to explore the calls to the CSP REST API.

# Tutorial

After downloading cspcli.py to your local machine, launch the application with the following command:

```
python cspcli.py
```

The application command line should open. You can have a look at the commands supported and some of the command options like this:

```
csp> help
csp> show -h
csp> show --help
```

Most commands take information from environment variables. You can have a look at the environment variables like this:

```
csp> show variables
csp> show var customerId
```

The first thing you need to do is to assign some environment variables to describe access to your CSP account. It is strongly recommended to use a sandbox account for this purpose:

```
csp> set appId <put here the ID of the Web App of your CSP sandbox>
csp> set appSecret <put here the key for the Web App of your CSP sandbox>
csp> set cspTenantId <put here the CSP tenant ID for your CSP sandbox account>
csp> set cspUsername <put here a username with admin privilege for your CSP sandbox account>
```

You can save these variables in a json file, so that you can retrieve them easily the next time you start your application
```
csp> save sandbox.json
sandbox>
```

Note that the prompt will change when you use the save or the load commands. Next time you open the application, you can just load the values from the JSON file created in the previous step:

```
python cspcli.py
csp> load sandbox.json
sandbox>
```

Now it is time to do our first REST API call, which will be to authenticate the app. CSP authentication can be app-based or app-and-user-based, as described here: https://msdn.microsoft.com/en-us/library/partnercenter/mt634709.aspx. For most operations you just need app-only authentication:

```
sandbox> set cspToken apponly
```

If you want to know exactly what REST API call a certain command did, you can use the option --verbose or -v. For example, issue another token, this time with the --verbose option:

```
sandbox> set cspToken apponly -v
```

An environment with the token value should have been set:

```
sandbox> show var cspToken
```

To verify that the token is working, let's show the list of customers defined in the CSP account:

```
sandbox> show customers
```

Now let's define a new customer, and verify that it has been created:

```
sandbox> add customer <your customer name>
sandbox> show customers
sandbox> show variable customerId
```

As you can see, the app took some default values for customer parameters such as the domain. The code is easily modifiable to allow for further customization. As you can see, there are no subscriptions created for our new customer. Notice that the command 'show subscriptions' will use per default the environment value 'customerId', but you could have specified a customer name or GUID like 'show subscriptions contoso': 

```
sandbox> show subscriptions
```

Our next step is creating an Azure subscription for our new customer:

```
sandbox> add subscription
sandbox> show subscriptions
sandbox> show variable subscriptionId
```

As next step, we need credentials that work in the newly created customer. First thing to verify is whether your AD app has been defined as multitenant. You can verify that with this command:

```
sandbox> show app
```

Notice the column 'AvailableToOtherTenants' (might be truncated to something shorter like 'Available'). If the Web App AvailableToOtherTenants is set to False, you need to change that. You can do it following the instructions here: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-integrating-applications

The last step is configuring the newly created subscription to accept authentication from our app. I haven't found a way of doing that over standard APIs, so I defined an Azure Function that does the job. This Azure Function needs user credentials in order to log into the Azure subscription, create a service principal associated to our app, and assign the role of 'Contributor' to that service principal for the whole subscription. 

```
sandbox> set cspUsername yourusername@yourcspsandboxdomain.onmicrosoft.com
sandbox> add role
```


For reference, here is the code for the Azure Function:

```
# POST method: $req
$requestBody = Get-Content $req -Raw | ConvertFrom-Json
$subscription = $requestBody.subscription
$appId = $requestBody.appId
$tenantId = $requestBody.tenantId
$user = $requestBody.user
$password = $requestBody.password

# Login
$secPassword = ConvertTo-SecureString $password -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ($user, $secPassword)
Login-AzureRmAccount -Credential $mycreds -TenantId $tenantId
Select-AzureRmSubscription -SubscriptionId $subscription

# Verify no Service Principal exists for our app yet
$principal = Get-AzureRmADServicePrincipal | ? ApplicationId -eq $appId

# Create SP for multitenant app
if ($principal.Count -eq 0) {
    $principal = New-AzureRmADServicePrincipal -ApplicationId $appid
    # Verify new Service Principal exists now
    $principal = Get-AzureRmADServicePrincipal | ? ApplicationId -eq $appId
    if ($principal.Count -eq 1) {
        $spMessage = "New service principal successfully created, OID " + $principal.Id
    } else {
        $spMessage = "Service Principal creation does not seem to have worked too well..."
    }
} else {
    $spMessage = "There is already a service principal for app ID " + $appId + ', OID ' + $principal.Id + ', skipping service principal creation'
}
$role = Get-AzureRmRoleAssignment | ? objectid -eq $principal.Id
if ($role.Count -eq 0) {
    # Assign Owner role (or contributor, or something else)
    New-AzureRmRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $appid
    $role = Get-AzureRmRoleAssignment | ? objectid -eq $principal.Id
    if ($role.Count -eq 1) {
        $roleMessage = "Role " + $role.RoleDefinitionName + " successfully assigned to service principal"
    } else {
        $roleMessage = "Role assignment does not seem to have worked too well..."
    }
} else {
    $roleMessage = "Service principal already has the role " + $role.RoleDefinitionName + " assigned, skipping role assignment"
}

$output = @{}
$output.add('servicePrincipal', $spMessage)
$output.add('roleAssignment', $roleMessage)
$outputJson = $output | convertTo-Json

Out-File -Encoding Ascii -FilePath $res -inputObject $outputJson
```

Now we should be able to generate an ARM token for the subscription, and do something with it. In this example we will just create a resource group in the new subscription. Please make sure that at least 3 minutes have passed after the customer creation, since that is more or less the time it takes for the customer to be fully provisioned.

```
sandbox> set armtoken
sandbox> show rg
sandbox> add rg <your resource group name> westeurope
sandbox> show rg
```