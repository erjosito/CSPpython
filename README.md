# Python CSP module and CSP CLI application

This repository contains cspcli.py, a python module with functions to interact with the CSP REST API.

The module contains as well a shell application, that can be used in order to explore the calls to the CSP REST API.

Additionally, you can find a sample script createCustomer.py, that shows how to import the functions of the module.

## Using the CSPCLI module

Download the cspcli.py file to a directory in your machine from where you can import modules. You can then import the functions you require (at least the login function). Check the script createCustomer.py for an example where the functions cspLogin and addCustomer are imported (works when cspcli.py and createCustomer.py are in the same directory).

## CSPCLI Tutorial

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
sandbox> set cspToken
```

If you want to know exactly what REST API call a certain command did, you can use the option --verbose or -v. For example, issue another token, this time with the --verbose option:

```
sandbox> set cspToken -v
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

The last step is authenticating to the ARM API for the newly created subscription. For that we will leverage app+user authentication, where we will use a special app assigned for Powershell, that is encoded in the Python module.

Now we should be able to generate an ARM token for the subscription, and do something with it. In this example we will just create a resource group in the new subscription. Please make sure that at least 3 minutes have passed after the customer creation, since that is more or less the time it takes for the customer to be fully provisioned. In order to use app+user authentication, you will need to specify as an environment variable a username with CSP admin privilege, and the token generation process will prompt you for the password for that user. 

```
sandbox> set variable cspUsername adminuser@yourcspdomain.onmicrosoft.com
sandbox> set armtoken --userauth
Please enter the password for user adminuser@yourcspdomain.onmicrosoft.com:
```

Finally, we can verify that the ARM token is working by creating any given resource in the new subscription. For the test we will use a Resource Group (does not cost any money). The following three commands list the existing resource groups in the subscription (there should not be anything yet), then create a new one, and lastly verify that it was successfully created.

```
sandbox> show rg
sandbox> add rg <your resource group name> westeurope
sandbox> show rg
```