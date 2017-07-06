from __future__ import print_function
import datetime
import requests
import simplejson
import cmd2
import sys
import os
import datetime
import re
import string
import random
import getpass

AZURE_OFFER_ID = 'MS-AZR-0146P'

##################
# Authentication #
##################

# Get token for CSP with app auth
def csplogin(tenantId, appId, appSecret, loginUrl="login.windows.net", graphUrl="graph.windows.net", verbose=False):
    url = 'https://' + loginUrl + '/'+ tenantId + '/oauth2/token'
    data = 'grant_type=client_credentials&resource=https%3A%2F%2F' + graphUrl + '&client_id=' + appId + '&client_secret=' + appSecret
    if verbose:
        print('VERBOSE - *************** REST API CALL - BEGIN *************** ')
        print('VERBOSE - POST to URL %s' % url)
        print('VERBOSE - NO HEADERS')
        print('VERBOSE - DATA: %s' % data)
        print('Calling REST API...')
    response = requests.post(url, data=data)
    if response.status_code == 200:
        if verbose:
            print('VERBOSE - RETURN CODE ' + str(response.status_code))
            print('VERBOSE - RESPONSE %s' % response.text)
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
        try:
            jsonResponse = response.json()
            token = jsonResponse['access_token']
            return token
        except:
            print('Could not extract token from answer')
            return False
    else:
        print ("Error: RETURN CODE " + str(response.status_code))
        if verbose:
            print('VERBOSE - RESPONSE %s' % response.text)
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
        return False

# Get token for CSP with app+user auth
def csploginUser(tenantId, appId, username, loginUrl="login.windows.net", verbose=False):
    url = 'https://' + loginUrl + '/'+ tenantId + '/oauth2/token'
    password = getpass.getpass('Password for user %s: ' % username)
    data = 'grant_type=password&resource=https%3A%2F%2Fapi.partnercenter.microsoft.com&client_id=' + appId + '&username=' + username + '&password=' + password
    if verbose:
        print('VERBOSE - *************** REST API CALL - BEGIN *************** ')
        print('VERBOSE - POST to URL %s' % url)
        print('VERBOSE - NO HEADERS')
        print('VERBOSE - DATA: %s' % data)
        print('Calling REST API...')
    response = requests.post(url, data=data)
    if response.status_code == 200:
        if verbose:
            print('VERBOSE - RETURN CODE ' + str(response.status_code))
            print('VERBOSE - RESPONSE %s' % response.text)
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
        try:
            jsonResponse = response.json()
            token = jsonResponse['access_token']
            return token
        except:
            print('Could not extract token from answer')
            return False
    else:
        print ("Error: RETURN CODE " + str(response.status_code))
        if verbose:
            print('VERBOSE - RESPONSE %s' % response.text)
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
        return False

# ARM login with app-only auth
def armlogin(tenantId, appId, appSecret, loginUrl="login.microsoftonline.com", verbose=False):
    url = 'https://' + loginUrl + '/'+ tenantId + '/oauth2/token?api-version=1.0'
    data = 'grant_type=client_credentials&resource=https%3A%2F%2Fmanagement.azure.com%2F&client_id=' + appId + '&client_secret=' + appSecret
    if verbose:
        print('VERBOSE - *************** REST API CALL - BEGIN *************** ')
        print('VERBOSE - POST to URL %s' % url)
        print('VERBOSE - NO HEADERS')
        print('VERBOSE - DATA: %s' % data)
        print('Calling REST API...')
    response = requests.post(url, data=data)
    if response.status_code == 200:
        if verbose:
            print('VERBOSE - RETURN CODE ' + str(response.status_code))
            print('VERBOSE - RESPONSE %s' % response.text)
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
        jsonResponse = response.json()
        token = jsonResponse['access_token']
        return token
    else:
        print ("Error: RETURN CODE " + str(response.status_code))
        if verbose:
            print('VERBOSE - RESPONSE %s' % response.text)
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
        return False

# ARM login with app+user auth
def armloginUser(tenantId, username, loginUrl="login.microsoftonline.com", verbose=False):
    appId = '1950a258-227b-4e31-a9cf-717495945fc2'
    password = getpass.getpass('Please enter the password for user %s: ' % username)
    if not password:
        return False
    url = 'https://' + loginUrl + '/'+ tenantId + '/oauth2/token?api-version=1.0'
    data = 'grant_type=password&resource=https%3A%2F%2Fmanagement.azure.com%2F&client_id=' + appId + '&username=' + username + '&password=' + password + '&scope=openid' 
    if verbose:
        print('VERBOSE - *************** REST API CALL - BEGIN *************** ')
        print('VERBOSE - POST to URL %s' % url)
        print('VERBOSE - NO HEADERS')
        print('VERBOSE - DATA: %s' % data)
        print('Calling REST API...')
    response = requests.post(url, data=data)
    if response.status_code == 200:
        if verbose:
            print('VERBOSE - RETURN CODE ' + str(response.status_code))
            print('VERBOSE - RESPONSE %s' % response.text)
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
        jsonResponse = response.json()
        token = jsonResponse['access_token']
        return token
    else:
        print ("Error: RETURN CODE " + str(response.status_code))
        if verbose:
            print('VERBOSE - RESPONSE %s' % response.text)
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
        return False


# Using AAD Graph (graph.windows.net), eventually to be migrated to Microsoft Graph (graph.microsoft.com)
def graphLogin(tenantId, appId, appSecret, loginUrl="login.microsoftonline.com", verbose=False):
    url = 'https://' + loginUrl + '/'+ tenantId + '/oauth2/token'
    data = 'grant_type=client_credentials&resource=https%3A%2F%2Fgraph.windows.net%2F&client_id=' + appId + '&client_secret=' + appSecret
    if verbose:
        print('VERBOSE - *************** REST API CALL - BEGIN *************** ')
        print('VERBOSE - POST to URL %s' % url)
        print('VERBOSE - NO HEADERS')
        print('VERBOSE - DATA: %s' % data)
        print('Calling REST API...')
    response = requests.post(url, data=data)
    if response.status_code == 200:
        if verbose:
            print('VERBOSE - RETURN CODE ' + str(response.status_code))
            print('VERBOSE - RESPONSE %s' % response.text)
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
        jsonResponse = response.json()
        token = jsonResponse['access_token']
        return token
    else:
        print ("Error: RETURN CODE " + str(response.status_code))
        if verbose:
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
            print('VERBOSE - RESPONSE %s' % response.text)
        return False


#######################
# Azure Function Hack #
#######################

def createSPandAssignRole (user, customerId, subscriptionId, appId, verbose=False):
    url = 'https://cspfunctions.azurewebsites.net/api/createContributorSP'
    password = getpass.getpass('Please enter password for user %s: ' % user)
    payload = {'user': user, 'password': password, 'tenantId': customerId, 'subscription': subscriptionId, 'appId': appId}
    textPayload = simplejson.dumps(payload)
    if verbose:
        print('VERBOSE - *************** REST API CALL - BEGIN *************** ')
        print('VERBOSE - POST to URL %s' % url)
        print('VERBOSE - NO HEADERS')
        print('VERBOSE - DATA: %s' % textPayload)
        print('Calling REST API...')
    response = requests.post(url, data=textPayload)
    if response.status_code == 200:
        if verbose:
            print('VERBOSE - RETURN CODE ' + str(response.status_code))
            print('VERBOSE - RESPONSE %s' % response.text)
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
        jsonResponse = response.json()
        return jsonResponse
    else:
        print ("Error: RETURN CODE " + str(response.status_code))
        if verbose:
            print('VERBOSE - RESPONSE %s' % response.text)
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
        return False

###########
# CSP API #
###########

def cspGetTenantId(token, customerName, verbose=False):
    url = 'https://api.partnercenter.microsoft.com/v1/customers'
    jsonResponse = sendRequest('GET', url, token, verbose=verbose)
    if jsonResponse:
        customers = jsonResponse["items"]
        for cust in customers[:]:
            if cust['companyProfile']['companyName'] == customerName:
                return cust['companyProfile']['tenantId']

def getCustomerId(token, customerName, verbose=False):
    url = 'https://api.partnercenter.microsoft.com/v1/customers'
    jsonResponse = sendRequest('GET', url, token, verbose=verbose)
    if jsonResponse:
        customers = jsonResponse["items"]
        for cust in customers[:]:
            if str(cust['companyProfile']['companyName']) == customerName:
                return cust['id']
        return False

def getCustomerList(token, verbose=False):
    url = 'https://api.partnercenter.microsoft.com/v1/customers'
    jsonResponse = sendRequest('GET', url, token, verbose=verbose)
    if jsonResponse:
        myList = []
        customers = jsonResponse["items"]
        for cust in customers[:]:
            myList.append({'id': cust['id'], 'name': cust['companyProfile']['companyName']})
            # DEBUG:
            #print (cust['companyProfile']['companyName'])
        return myList


def getSubscriptions(token, customerId, onlyAzure=True, verbose=False):
    url = 'https://api.partnercenter.microsoft.com/v1/customers/' + customerId + '/subscriptions'
    jsonResponse = sendRequest('GET', url, token, verbose=verbose)
    if jsonResponse:
        #if jsonResponse['totalCount'] > 1:
        #    print ("WARNING, " + str(jsonResponse['totalCount']) + ' subscriptions found for that customer')
        myList = []
        subs = jsonResponse["items"]
        for sub in subs[:]:
            if (not onlyAzure) or (sub['offerName'] == 'Microsoft Azure'):
                myList.append({'id': sub['id'], 'name': sub['friendlyName']})
        return myList
        #return subs[0]['id']

# This function takes as argument a previously built dictionary
#   that maps consumption IDs to ARM resource IDs
def getResourceConsumption(token, customerId, subscriptionId, myDict, verbose=False):
    url = 'https://api.partnercenter.microsoft.com/v1/customers/' + customerId + '/subscriptions/' + subscriptionId + '/usagerecords/resources'
    jsonResponse = sendRequest('GET', url, token, verbose=verbose)
    if jsonResponse:
        myList = []
        records = jsonResponse["items"]
        #print str(jsonResponse['totalCount']) + " resource usage records found"
        for record in records[:]:
            if record['totalCost'] > 0:
                resourceId = record['resourceId'].lower()
                resourceUri = getResourceUri(myDict, resourceId)
                myList.append({"category": record['category'], 'subcategory': record['subcategory'], 'resourceId': resourceId, 'resourceUri': resourceUri, 'totalCost': record['totalCost']})
                #print ('%20s %20s %10s %15s %30s' % (record['category'], record['subcategory'], record['totalCost'], resourceId, resourceUri))
        return myList

def getConsumptionSummary(token, customerId, verbose=False):
    #url = 'https://api.partnercenter.microsoft.com/v1/customers/{{CustomerId}}/subscriptions/{{SubscriptionId}}/usagesummary'
    # First browse all subscriptions
    url = 'https://api.partnercenter.microsoft.com/v1/customers/' + customerId + '/subscriptions'
    jsonResponse = sendRequest('GET', url, token, verbose=verbose)
    if jsonResponse:
        myList = []
        subs = jsonResponse["items"]
        for sub in subs[:]:
            subscriptionId = sub['id']
            url2 = 'https://api.partnercenter.microsoft.com/v1/customers/' + customerId + '/subscriptions/' + subscriptionId + '/usagesummary'
            jsonResponse2 = sendRequest('GET', url2, token, verbose=verbose)
            totalCost = 0
            try:
                totalCost = jsonResponse2['totalCost']
                myList.append({'subscriptionId': subscriptionId.lower(), 'totalCost': totalCost})
                #print (subscriptionId + ": " + str(totalCost))
            except:
                pass
        return myList


def cspGetResourceUri(token, customerId, subscriptionId, resourceGuid, verbose=False):
    # This function makes API calls per each customer ID
    # It is much more efficient building once a "translation dictionary", so that not so many REST calls are made
    url = 'https://api.partnercenter.microsoft.com/v1/customers/' + customerId + '/subscriptions/' + subscriptionId + '/utilizations/azure'
    now = datetime.datetime.now()
    day1 = str(now.year) + '-' + str(now.month) + '-01'
    dayn = str(now.year) + '-' + str(now.month) + '-28'
    timeFilter = '?start_time=' + day1 + 'T00%3a00%3a00%2b00%3a00&end_time=' + dayn + 'T23%3a59%3a59%2b00%3a00'
    otherOptions = '&granularity={granularity}&show_details=True&size=100'
    url = url + timeFilter + otherOptions
    jsonResponse = sendRequest('GET', url, token, textPayload=None, verbose=verbose)
    if jsonResponse:
        records = jsonResponse["items"]
        for record in records[:]:
            resourceId = ''
            try:
                resourceId = record['resource']['id']
            except:
                print ('Error when evaluating utilization record')
                pass
            if resourceId == resourceGuid:
                return record['instanceData']['resourceUri']

# Builds a dictionary that maps consumption resource IDs to ARM IDs, including ARM tags 
def buildResourceDict(token, customerId, subscriptionId, verbose=False):
    url = 'https://api.partnercenter.microsoft.com/v1/customers/' + customerId + '/subscriptions/' + subscriptionId + '/utilizations/azure'
    now = datetime.datetime.now()
    day1 = str(now.year) + '-' + str(now.month) + '-01'
    dayn = str(now.year) + '-' + str(now.month) + '-28'
    timeFilter = '?start_time=' + day1 + 'T00%3a00%3a00%2b00%3a00&end_time=' + dayn + 'T23%3a59%3a59%2b00%3a00'
    otherOptions = '&granularity={granularity}&show_details=True&size=100'
    url = url + timeFilter + otherOptions
    jsonResponse = sendRequest('GET', url, token, textPayload=None, verbose=verbose)
    if jsonResponse:
        myDict = []
        records = jsonResponse["items"]
        # DEBUG:
        #print "Total records in resource consumption data: " + str(len(records))
        counter = 0
        for record in records[:]:
            counter += 1
            resourceId = ""
            resourceUri = ""
            resourceTags = []
            try:
                resourceId = record['resource']['id'].lower()
                resourceUri = record['instanceData']['resourceUri']
                resourceTags = record['instanceData']['tags']
            except:
                pass
            # DEBUG:
            #print 'Record ' + str(counter) + ' info: ' + resourceId + ', ' + resourceUri + ', ' + json.dumps(resourceTags)
            if not inDict(myDict, resourceId):
                myDict.append({"id": resourceId, "uri": resourceUri, "tags": resourceTags})
        return myDict

def addCustomer(customerName, token, verbose=False):
    url = 'https://api.partnercenter.microsoft.com/v1/customers'
    now = datetime.datetime.now()
    timesuffix = str(now.year) + str(now.month) + str(now.day) + str(now.hour) + str(now.minute) 
    payload = {'Id': None,
               'CommerceId': None, 
               'CompanyProfile': {'TenantId': None, 'Domain': 'mysample'+timesuffix+'.onmicrosoft.com', 'CompanyName': customerName,
                    'Attributes': {'ObjectType': 'CustomerCompanyProfile'}},
               'BillingProfile': {'Id': None, 'FirstName': 'John', 'LastName': 'Doe', 'Email': 'SomeEmail@outlook.com',
                    'Culture': 'EN-US', 'Language': 'En', 'CompanyName': customerName,
                    'DefaultAddress': {'Country': 'US', 'Region': None, 'City': 'Redmond', 'State': 'WA',
                        'AddressLine1': 'One Microsoft Way', 'AddressLine2': None, 'PostalCode': '98052',
                        'FirstName': 'John', 'LastName': 'Doe', 'PhoneNumber': None},
                    'Attributes': {'ObjectType': 'CustomerBillingProfile'}},
                'RelationshipToPartner': 'none',
                'AllowDelegatedAccess': None,
                'UserCredentials': None,
                'CustomDomains': None,
                'AssociatedPartnerId': None,
                'Attributes': {'ObjectType': 'Customer'}}
    textPayload = simplejson.dumps(payload)
    jsonResponse = sendRequest('POST', url, token, textPayload, verbose)
    if jsonResponse:
        return jsonResponse

def deleteCustomer(customerId, token, verbose=False):
    url = 'https://api.partnercenter.microsoft.com/v1/customers/' + customerId 
    sendRequest ('DELETE', url, token, verbose=verbose)


def getOffers(token, countryCode='US', verbose=False):
    url = 'https://api.partnercenter.microsoft.com/v1/offers?country=' + countryCode
    jsonResponse = sendRequest('GET', url, token, verbose=verbose)
    if jsonResponse:
        offers = jsonResponse["items"]
        offersTable = []
        for offer in offers[:]:
            offersTable.append({'id': offer['id'], 'name': offer['name'], 'country': offer['country']})
        return offersTable

def addOrder(token, customerId, offerId=AZURE_OFFER_ID, verbose=False):
    url = 'https://api.partnercenter.microsoft.com/v1/customers/' + customerId + '/orders'
    headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json', 'Content-Type': 'application/json'}
    payload = {'Id': None, 'ReferenceCustomerId': customerId, 'BillingCycle': 'unknown',
               'LineItems': [{
                    'LineItemNumber': 0, "OfferId": offerId, "SubscriptionId": None, 'Friendly Name': 'New offer', 'Quantity': 1, 'PartnerIdOnRecord': None,
                    'Attributes': { 'ObjectType': 'OrderLineItem' }
               }],
               'CreationDate': None,
               'Attributes': {'ObjectType': 'Order'}}
    textPayload = simplejson.dumps(payload)
    jsonResponse = sendRequest('POST', url, token, textPayload, verbose)
    if jsonResponse:
        return jsonResponse

def addUser(token, customerId, userName, password, userFirstName, userLastName, userLocation='US', verbose=False):
    url = 'https://api.partnercenter.microsoft.com/v1/customers/' + customerId + '/users'
    payload = {'usageLocation': userLocation, 'userPrincipalName': userName, 'firstName': userFirstName, 'lastName': userLastName, 'displayName': userFirstName + ' ' + userLastName,
               'passwordProfile': {'password': password, 'forceChangePassword': True},
               'Attributes': {'ObjectType': 'CustomerUser'}}
    textPayload = simplejson.dumps(payload)
    response = sendRequest('POST', url, token, textPayload, verbose)
    return response

##################
#  ARM REST API  #
##################

def getResourceGroups(token, subscriptionId, verbose=False):
    url = 'https://management.azure.com/subscriptions/' + subscriptionId + '/resourcegroups?api-version=2016-09-01'
    jsonResponse = sendRequest('GET', url, token, textPayload=None, verbose=verbose)
    if jsonResponse:
        groups = jsonResponse["value"]
        myGroups = []
        for group in groups[:]:
            myGroups.append({'id': group['id'], 'name': group['name'], 'location': group['location']})
        return myGroups

def createResourceGroup(token, subscriptionId, name, location, verbose=False):
    url = 'https://management.azure.com/subscriptions/' + subscriptionId + '/resourcegroups/' + name + '?api-version=2016-09-01'
    payload = {"location": location}
    textPayload = simplejson.dumps(payload)
    jsonResponse = sendRequest('PUT', url, token, textPayload, verbose)
    return jsonResponse

##################
# Graph REST API #
##################

def getGraphTenantInfo(customerId, appId, appSecret, verbose=None):
    graphToken = graphLogin(customerId, appId, appSecret, verbose)
    if graphToken:
        url = 'https://graph.windows.net/' + customerId + '/tenantDetails?api-version=1.6'
        response = sendRequest('GET', url, graphToken, verbose=verbose)
        return response
    else:
        print("Error while trying to get token for Graph API for tenant %s" % customerId)

# Request authorization code
def buildGraphAuthCodeRequest(customerId, appId):
    url = 'https://login.microsoftonline.com/' + customerId + '/oauth2/authorize?'
    url += 'client_id=' + appId
    url += '&response_type=code'
    url += '&redirect_uri=http%3A%2F%2Flocalhost%2F' 
    url += '&response_mode=query'
    # Identifier URI of the App
    url += '&resource=https%3A%2F%2Fcspcsap.onmicrosoft.com%2F81c0ed80-86f4-4522-80a4-24f6559527b9'
    return url

def getApps(token, customerId, graphUrl="graph.windows.net", details=None, verbose=None):
    url = 'https://' + graphUrl + '/' + customerId + '/applications?api-version=1.6'
    response = sendRequest('GET', url, token, verbose=verbose)
    if details:
        return response
    else:
        appList = []
        for app in response['value'][:]:
            appList.append({'displayName': app['displayName'], 'appId': app['appId'], 'objectId': app['objectId'], 'homepage': app['homepage'], 'identifierUris': app['identifierUris'], 'availableToOtherTenants': app['availableToOtherTenants']})
        return appList

def getSPs(token, customerId, details=None, verbose=None):
    url = 'https://graph.windows.net/' + customerId + '/servicePrincipals?api-version=1.6'
    response = sendRequest('GET', url, token, verbose=verbose)
    if details:
        return response
    else:
        spList = []
        for sp in response['value'][:]:
            spList.append({'appDisplayName': sp['appDisplayName'], 'appId': sp['appId'], 'objectId': sp['objectId'], 'servicePrincipalType': sp['servicePrincipalType']})
        return spList

#########################################################
# Functions to map ARM resources to consumption records #
#########################################################

def getResourceUri(myDict, myid):
    for item in myDict[:]:
        if item['id'] == myid:
            return item['uri']
    return 'URI not found'

def inDict(myDict, myid):
    for item in myDict[:]:
        if item['id'] == myid:
            return True
    return False


###############################
# Generic, non-API functions #
###############################

def printList(myList, widthList=None):
    # Print title, taking the keys of the first row
    index = 0
    for key in myList[0]:
        thisWidth = 20  # Default width if widthList not specified or incorrect
        if not widthList is None:
            try:
                thisWidth = widthList[index]
            except:
                pass
        print('{:{width}.{truncate}}'.format(key, width=thisWidth, truncate=thisWidth-1), end='')
        index += 1
    print('')
    # Print data
    for item in myList[:]:
        index = 0
        for key in item:
            thisWidth = 20  # Default width if widthList not specified or incorrect
            if not widthList is None:
                try:
                    thisWidth = widthList[index]
                except:
                    pass
            if isinstance(item[key], float):
                itemString = "{:.2f}".format(item[key])
            elif isinstance(item[key], int):
                itemString = str(item[key])
            else:
                itemString = item[key]
            print('{:{width}.{truncate}}'.format(itemString, width=thisWidth, truncate=thisWidth-1), end='')
            #print '{:{width}}'.format(item[key], width=thisWidth)
            index += 1
        print ('')

def generateRandomPassword(passlength=12):
    if passlength < 6:
        print("Minimum password length is 6")
    else:
        mypass = ''
        mypass += random.choice(string.ascii_lowercase)
        mypass += random.choice(string.ascii_uppercase)
        mypass += random.choice(string.digits)
        mypass += random.choice(['!', '*'])
        mypass += ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(passlength-4))
        return mypass

# Generic wrapper for the requests functions
def sendRequest(method, url, token=None, textPayload=None, verbose=False):
    method = method.upper()
    if token and method in ['POST', 'PUT']:
        headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json', 'Content-Type': 'application/json'}
    elif token and method in ['GET', 'DELETE']:
        headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}
    else:
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    if verbose:
        print('VERBOSE - *************** REST API CALL - BEGIN *************** ')
        print('VERBOSE - URL (%s): %s' % (method, url))
        print('VERBOSE - HEADERS: %s' % simplejson.dumps(headers))
        print('VERBOSE - PAYLOAD %s' % simplejson.dumps(textPayload))
        print('VERBOSE - Calling REST API...')
    if method == 'POST':
        response = requests.post(url, headers=headers, data=textPayload)
    elif method == 'PUT':
        response = requests.put(url, headers=headers, data=textPayload)
    elif method == 'GET':
        response = requests.get(url, headers=headers)
    elif method == 'DELETE':
        response = requests.delete(url, headers=headers)
    else:
        print('Method %s not supported' % method)
        return False
    if response.status_code < 300:
        if verbose:
            print("VERBOSE - RETURN CODE: %s" % str(response.status_code))
            print("VERBOSE - ANSWER: %s" % str(response.text.encode('utf-8')))
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
        if response.text:
            jsonResponse = simplejson.loads(response.text)
            return jsonResponse
    else:
        print("ERROR: RETURN CODE " + str(response.status_code))
        if verbose:
            print("VERBOSE - ANSWER: %s" % str(response.text.encode('utf-8')))
            print('VERBOSE - ***************  REST API CALL - END  *************** ')
        return False

def showDict(mydict):
    # Print the value of the global variables
    for item in mydict:
        print ('%s: %s' % (item, mydict[item]))

def saveDict(mydict, filename):
    jsonstring = simplejson.dumps(mydict)
    #print "Saving string %s" % jsonstring
    try:
        with open(filename, "w") as myfile:
            myfile.write(jsonstring)
    except Exception as e:
        print ("Error writing to %s" % filename)
        #print e

def isGuid(myguid):
    pattern = re.compile('^[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}$')
    return pattern.match(myguid)

def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

############################
# cmd2 class for shell app #
############################

class CmdLineApp(cmd2.Cmd):
    """ cmd2-based application for CSP management """
    prompt = 'csp> '

    # Global variables in a dictionary
    variables = {"cspTenantId": None, "appId": None, "appSecret": None, 
                 "customerId": None, "subscriptionId": None, "cspToken": None, "armToken": None, 'nativeAppId': None, 
                 "cspUsername": None, "graphUrl": "graph.windows.net", "loginUrl": "login.microsoftonline.com"}

    # Setting this true makes it run a shell command if a cmd2/cmd command doesn't exist
    default_to_shell = True

    def __init__(self):
        # Set use_ipython to True to enable the "ipy" command which embeds and interactive IPython shell
        cmd2.Cmd.__init__(self, use_ipython=False)

    ########
    # SHOW #
    ########
    @cmd2.options([cmd2.make_option('-v', '--verbose', action="store_true", help="show REST API info"),
                   cmd2.make_option('-d', '--details', action='store_true', help='show additional details')])
    def do_show(self, line, opts=None):
        '''
        Show some information, depending on the following argument. Commands supported:
            show customers
            show subscriptions
            show consumption
            show consumption details
            show variables
            show offers
            show offers US
            show apps
            show apps --details
            show sp
            show sp --details
            show rg
        '''
        args = line.split()
        if len(args) < 1:
            print ("Not enough arguments provided, please type 'help show' for information on this command")
            return False
        mycmd = args[0].lower()

        # Show variables
        if mycmd[:3] == 'var':
            if len(args) > 1:
                print(self.variables[args[1]])
            else:
                showDict(self.variables)

        # Show customers
        elif mycmd[:2] == 'cu':
            customerList = getCustomerList(self.variables['cspToken'], verbose=opts.verbose)
            if customerList:
                print('CUSTOMER LIST:')
                printList(customerList, [45, 40])

        # Show subscriptions
        elif mycmd[:3] == 'sub':
            if self.variables['cspToken']:
                subscriptionList = None
                if len(args) > 1:
                    customerId = args[1]
                    if isGuid(customerId):
                        subscriptionList = getSubscriptions(self.variables['cspToken'], customerId, verbose=opts.verbose)
                    else:
                        print('%s does not seem to be a valid GUID format, trying it as customer name' % customerId)
                        customerName = customerId
                        customerId = getCustomerId(self.variables['cspToken'], customerName, opts.verbose)
                        if customerId and isGuid(customerId):
                            subscriptionList = getSubscriptions(self.variables['cspToken'], customerId, verbose=opts.verbose)
                        else:
                            print('No customer was found named %s' % customerName)
                elif self.variables['customerId'] and isGuid(self.variables['customerId']):
                    customerId = self.variables['customerId']
                    subscriptionList = getSubscriptions(self.variables['cspToken'], customerId, verbose=opts.verbose)
                else:
                    print("The customerId variable does not seem to be set, please make sure you define one with the command 'set customerId'")

                if subscriptionList:
                    print('SUBSCRIPTION LIST FOR CUSTOMER ID ' + self.variables['customerId'] + ':')
                    printList(subscriptionList, [45, 50])
            else:
                print ("Please make sure to generate a CSP token with 'set token'")

        # Show offers
        elif mycmd[:3] == 'off':
            if self.variables['cspToken']:
                offersList = None
                if len(args) > 1:
                    countryCode = args[1]
                    if len(countryCode) == 2:
                        offersList = getOffers(self.variables['cspToken'], countryCode, verbose=opts.verbose)
                    else:
                        print('%s does not seem to be a valid country format, try with a 2-letter code such as US' % customerId)
                else:
                    countryCode = 'US'
                    offersList = getOffers(self.variables['cspToken'], countryCode, verbose=opts.verbose)
                if offersList:
                    print('OFFER LIST FOR CUSTOMER ID ' + countryCode + ':')
                    printList(offersList, [4, 40, 40])
            else:
                print ("Please make sure to generate a CSP token with 'set token'")

        # Show Consumption Resources
        elif mycmd[:3] == 'con':
            if self.variables['cspToken'] and self.variables['customerId']:
                if len(args) > 1:
                    if args[1][:3] == 'det' and self.variables['subscriptionId']:
                        # Get consumption by resource. Build a dictionary that gives additional info
                        #   for each resource ID (or resource GUID, properly said)
                        myDict = buildResourceDict(self.variables['cspToken'], self.variables['customerId'], self.variables['subscriptionId'], verbose=opts.verbose)
                        # DEBUG DICTIONARY
                        #printList (myDict, [50, 45, 50])
                        resourceConsumption = getResourceConsumption(self.variables['cspToken'], self.variables['customerId'], self.variables['subscriptionId'], myDict, verbose=opts.verbose)
                        if resourceConsumption:
                            print('RESOURCE CONSUMPTION SUMMARY FOR CUSTOMER ID ' + self.variables['customerId'] + ', SUBSCRIPTION ID ' + self.variables['subscriptionId'] + ':')
                            printList(resourceConsumption, [10, 45, 10, 20, 40])
                    elif args[1][:3] == 'det' and not self.variables['subscriptionId']:
                        print ("For consumption details, please make sure that you have set the subscription ID variable with the 'set' command")
                    else:
                        print ("Option for show consumption command not recognized, please type 'help show' for information on this command")
                else:
                    print('Getting non-zero consumption summary for all subscriptions...')
                    consumptionSummary = getConsumptionSummary(self.variables['cspToken'], self.variables['customerId'], verbose=opts.verbose)
                    if consumptionSummary:
                        print('CONSUMPTION SUMMARY FOR CUSTOMER ID ' + self.variables['customerId'] + ':')
                        printList(consumptionSummary, [10, 45])
            else:
                print ("Please make sure to specify a customer ID and generate a CSP token")

        # Show Resource Groups
        elif mycmd[:2] == 'rg':
            if not self.variables['armToken']:
                print("You need to set an ARM token with the command 'set armtoken'")
                return False
            if not self.variables['subscriptionId']:
                print("You need to set a subscription ID with the command 'set subscriptionId'")
                return False
            rgs = getResourceGroups(self.variables['armToken'], self.variables['subscriptionId'], verbose=opts.verbose)
            if rgs:
                print('RESOURCE GROUPS IN SUBSCRIPTION %s' %self.variables['subscriptionId'])
                printList(rgs, [15, 80, 20])

        # Show Apps
        elif mycmd[:3] == 'app':
            if self.variables['appId'] and self.variables['appSecret'] and self.variables['cspTenantId']:
                cspGraphToken = graphLogin(self.variables['cspTenantId'], self.variables['appId'], self.variables['appSecret'], loginUrl=self.variables['loginUrl'], verbose=opts.verbose)
                if cspGraphToken:
                    if opts.verbose:
                        print('VERBOSE - Graph token obtained successfully for CSP Tenant ID %s' % self.variables['cspTenantId'])
                    if opts.details:
                        appJson = getApps(cspGraphToken, self.variables['cspTenantId'], graphUrl=self.variables['graphUrl'], verbose=opts.verbose, details=opts.details)
                        print(simplejson.dumps(appJson, indent=4))
                    else:
                        appList = getApps(cspGraphToken, self.variables['cspTenantId'], graphUrl=self.variables['graphUrl'], verbose=opts.verbose, details=opts.details)
                        if appList:
                            print('APPLICATIONS in CSP TENANT ID %s:' % self.variables['cspTenantId'])
                            printList(appList, [20, 37, 20, 10, 37, 20])
            else:
                print("You need to set the varialbes 'cspTenantId', 'appId' and 'appSecret'")
                return False

        # Show Service Principals
        elif mycmd[:2] == 'sp':
            if self.variables['appId'] and self.variables['appSecret'] and self.variables['cspTenantId']:
                cspGraphToken = graphLogin(self.variables['cspTenantId'], self.variables['appId'], self.variables['appSecret'], opts.verbose)
                if cspGraphToken:
                    if opts.verbose:
                        print('VERBOSE - Graph token obtained successfully for CSP Tenant ID %s' % self.variables['cspTenantId'])
                    if opts.details:
                        spJson = getSPs(cspGraphToken, self.variables['cspTenantId'], verbose=opts.verbose, details=opts.details)
                        print(simplejson.dumps(spJson, indent=4))
                    else:
                        spList = getSPs(cspGraphToken, self.variables['cspTenantId'], verbose=opts.verbose, details=opts.details)
                        if spList:
                            print('SERVICE PRINCIPALS in CSP TENANT ID %s:' % self.variables['cspTenantId'])
                            printList(spList, [18, 37, 30, 37])
            else:
                print("You need to set the varialbes 'cspTenantId', 'appId' and 'appSecret'")
                return False


        else:
            print ("Command not supported, please type 'help show' for information on this command")

    #######
    # SET #
    #######
    @cmd2.options([cmd2.make_option('-v', '--verbose', action="store_true", help="show REST API info"),
                   cmd2.make_option('-u', '--userauth', action="store_true", help="login with app+user authentication")])
    def do_set(self, line, opts=None):
        '''
        Set a variable's value. Commands supported:
           set subscriptionId <a subscription ID>
           set customerId <a customer ID>
           set cspTenantId <a CSP partner tenant ID>
           set appId <your app ID for the CSP API>
           set appSecret <your app secret for the CSP API>
           set cspToken
           set cspToken --userauth
           set armToken
           set armToken --userauth
           set graphUrl
           set loginUrl
        '''
        args = line.split()
        if len(args) < 1:
            print ("Not enough arguments provided, please type 'help set' for information on this command")
            return False
        mycmd = args[0].lower()

        # Set subscription
        if mycmd[:3] == 'sub':
            if len(args) < 2:
                print ("Not enough arguments provided, please type 'help set' for information on this command")
                return False
            else:
                self.variables['subscriptionId'] = args[1] 

        # Set CSP tenant Id
        elif mycmd[:3] == 'ten' or mycmd[:5] == 'cspte':
            if len(args) < 2:
                print ("Not enough arguments provided, please type 'help set' for information on this command")
                return False
            else:
                self.variables['cspTenantId'] = args[1]

        # Set Graph API URL for CSP token app-only authentication 
        elif mycmd[:2] == 'gr':
            if len(args) < 2:
                print ("Not enough arguments provided, please type 'help set' for information on this command")
                return False
            else:
                self.variables['graphUrl'] = args[1]

        # Set Login URL for CSP and ARM authentication 
        elif mycmd[:2] == 'lo':
            if len(args) < 2:
                print ("Not enough arguments provided, please type 'help set' for information on this command")
                return False
            else:
                self.variables['loginUrl'] = args[1]

        # Set Native App Id
        elif mycmd[:3] == 'nat':
            if len(args) < 2:
                print ("Not enough arguments provided, please type 'help set' for information on this command")
                return False
            else:
                self.variables['nativeAppId'] = args[1]

        # Set CSP Username
        elif mycmd[:4] == 'cspu' or mycmd[:4] == 'user':
            if len(args) < 2:
                print ("Not enough arguments provided, please type 'help set' for information on this command")
                return False
            else:
                self.variables['cspUsername'] = args[1] 

        # Set appId 
        elif mycmd[:4] == 'appi':
            if len(args) < 2:
                print ("Not enough arguments provided, please type 'help set' for information on this command")
                return False
            else:
                self.variables['appId'] = args[1] 

        # Set appSecret
        elif mycmd[:4] == 'apps':
            if len(args) < 2:
                print ("Not enough arguments provided, please type 'help set' for information on this command")
                return False
            else:
                self.variables['appSecret'] = args[1] 

        # Set customerId
        elif mycmd[:3] == 'cus':
            if len(args) < 2:
                print ("Not enough arguments provided, please type 'help set' for information on this command")
                return False
            else:
                self.variables['customerId'] = args[1] 

        # Set CSP token
        elif mycmd[:5] == 'cspto':
            # App+User (default option)
            if opts.userauth:
                if self.variables['cspTenantId'] and self.variables['cspUsername'] and self.variables['nativeAppId']:
                    self.variables['cspToken'] = csploginUser(self.variables['cspTenantId'], self.variables['nativeAppId'], self.variables['cspUsername'], loginUrl=self.variables['loginUrl'], verbose=opts.verbose)
                    if self.variables['cspToken']:
                        print('CSP token set using App+User authentication')
                else:
                    print ("Please make sure you have set the variables cspTenantId, nativeAppId and cspUsername")
            # App Only
            else:
                if self.variables['cspTenantId'] and self.variables['appId'] and self.variables['appSecret']:
                    self.variables['cspToken'] = csplogin(self.variables['cspTenantId'], self.variables['appId'], self.variables['appSecret'], loginUrl=self.variables['loginUrl'], graphUrl=self.variables['graphUrl'], verbose=opts.verbose)
                    if self.variables['cspToken']:
                        print('CSP token set using App-only authentication')
                else:
                    print ("Please make sure you have set the variables cspTenantId, appId and appSecret")

        # Set ARM Token
        elif mycmd[:6] == 'armtok':
            self.variables['armToken'] = None
            # App+User auth
            if opts.userauth:
                # Username from the environment variables
                if self.variables['cspUsername']:
                    username = self.variables['cspUsername']
                    # Customer ID from environment variable or from command line
                    if len(args) > 1:
                        customerId = args[1]
                        if isGuid(customerId):
                            customerId = self.variables['customerId']
                        else:
                            print('%s does not seem to be a valid GUID format, trying it as customer name' % customerId)
                            customerName = customerId
                            customerId = getCustomerId(self.variables['cspToken'], customerName, opts.verbose)
                            if not (customerId and isGuid(customerId)):
                                print('No customer was found named %s' % customerName)
                                return False
                    elif self.variables['customerId'] and isGuid(self.variables['customerId']):
                        customerId = self.variables['customerId']
                    else:
                        print("The customerId variable does not seem to be set, please make sure you define one with the command 'set customerId'")
                        return False
                    self.variables['armToken'] = armloginUser(customerId, username, loginUrl=self.variables['loginUrl'], verbose=opts.verbose)
                    if self.variables['armToken']:
                        print('ARM token generated with app+password authentication')
                else:
                    print ("Please make sure you have set the environment variable cspUsername with the 'set cspUsername' command")
            # App-only Auth
            else:
                # App Id and App Secret from the environment variables
                if self.variables['appId'] and self.variables['appSecret']:
                    if len(args) > 1:
                        customerId = args[1]
                        if not isGuid(customerId):
                            print('%s does not seem to be a valid GUID format, trying it as customer name' % customerId)
                            customerName = customerId
                            customerId = getCustomerId(self.variables['cspToken'], customerName, opts.verbose)
                            if not (customerId and isGuid(customerId)):
                                print('No customer was found named %s' % customerName)
                                return False
                    elif self.variables['customerId'] and isGuid(self.variables['customerId']):
                        customerId = self.variables['customerId']
                    self.variables['armToken'] = armlogin(customerId, self.variables['appId'], self.variables['appSecret'], loginUrl=self.variables['loginUrl'], verbose=opts.verbose)
                    if self.variables['armToken']:
                        print("ARM token generated with app authentication, use the command 'show variable armToken' to verify its value")
                else:
                    print ("Please make sure you have set the environment variable cspUsername with the 'set cspUsername' command")

        # Set Graph Token
        elif mycmd[:5] == 'graph':
            if self.variables['appId'] and self.variables['appSecret'] and self.variables['customerId'] and isGuid(self.variables['customerId']):
                # Authorization code generation
                url = buildGraphAuthCodeRequest(self.variables['customerId'], self.variables['appId'])
                print('Please open this URL, and authenticate with a customer user: %s' % url)
                authToken = raw_input('Enter the code you received here: ')
                return False
            else:
                print ("Please make sure you have set the environment variables appId and appSecret with the 'set' command")


        # Whaaat?
        else:
            print ("Set command not recognized, please type 'help set' for information on this command")

    #######
    # ADD #
    #######
    @cmd2.options([cmd2.make_option('-v', '--verbose', action="store_true", help="show REST API info")])
    def do_add(self, line, opts=None):
        '''
        Add a new object. Commands supported:
           add customer
           add subscription
           add role
        '''
        args = line.split()
        if len(args) < 1:
            print("Not enough arguments provided, please type 'help add' for information on this command")
            return False
        mycmd = args[0].lower()
        if not self.variables['cspToken']:
            print("No CSP token seems to be set, please make sure you define one with the command 'set token'")

        # Add customer
        elif mycmd[:3] == 'cus':
            if len(args) < 2:
                print("Please enter a name for the customer to be added")
            else:
                jsonResponse = addCustomer(args[1], self.variables['cspToken'], opts.verbose)
                try:
                    self.variables['customerId'] = jsonResponse['id']
                except:
                    pass                    

        # Add subscription
        elif mycmd[:3] == 'sub':
            if len(args) > 1:
                customerId = args[1]
                if isGuid(customerId):
                    jsonResponse = addOrder(self.variables['cspToken'], customerId, verbose=opts.verbose)
                    try:
                        self.variables['subscriptionId'] = jsonResponse['lineItems'][0]['subscriptionId']
                    except:
                        pass                    
                else:
                    print('%s does not seem to be a valid GUID format, trying it as customer name' % customerId)
                    customerName = customerId
                    customerId = getCustomerId(self.variables['cspToken'], customerName, opts.verbose)
                    if customerId and isGuid(customerId):
                        jsonResponse = addOrder(self.variables['cspToken'], customerId, verbose=opts.verbose)
                    try:
                        self.variables['subscriptionId'] = jsonResponse['lineItems'][0]['subscriptionId']
                    except:
                        pass                    
                    else:
                        print('No customer was found named %s' % customerName)
            elif self.variables['customerId'] and isGuid(self.variables['customerId']):
                customerId = self.variables['customerId']
                jsonResponse = addOrder(self.variables['cspToken'], customerId, verbose=opts.verbose)
                try:
                    self.variables['subscriptionId'] = jsonResponse['lineItems'][0]['subscriptionId']
                except:
                    pass                    
            else:
                print("The customerId variable does not seem to be set, please make sure you define one with the command 'set customerId'")

        # Add Service Principal and Role Assignment
        elif mycmd[:4] == 'role':
            if self.variables['customerId'] and self.variables['subscriptionId'] and self.variables['cspUsername'] and self.variables['appId']:
                roleResponse = createSPandAssignRole(self.variables['cspUsername'], self.variables['customerId'], self.variables['subscriptionId'], self.variables['appId'], opts.verbose)
                if roleResponse and isinstance(roleResponse, dict):
                    for message in roleResponse.values():
                        print(message)
            else:
                print("The variables customerId, subscriptionId, appId and cspUsername do not seem to be set, please make sure you define them with 'set' commands")
        # Add user
        elif mycmd[:2] == 'us':
            if self.variables['customerId'] and isGuid(self.variables['customerId']):
                customerId = self.variables['customerId']
                customerInfo = getGraphTenantInfo(customerId, self.variables['appId'], self.variables['appSecret'], opts.verbose)
                try:
                    customerDomain = customerInfo['value'][0]['verifiedDomains'][0]['name']
                except:
                    print("ERROR: Not able to retrieve domain name for customer %s" % customerId)
                    return False
                if len(args) > 1:
                    userId = args[1]
                    userId = userId + '@' + customerDomain
                    try:
                        password = generateRandomPassword()
                    except:
                        print("ERROR: Random password could not be generated")
                        return False
                    print("Trying to create user with random password %s (needs to be changed at first login)" % password)
                    firstName = 'John'
                    lastName = 'Doe'
                    json = addUser(self.variables['cspToken'], customerId, userId, password, firstName, lastName, 'US', opts.verbose)
                else:
                    print("Please specify a user Id: 'add user johndoe'")
            else:
                print("The customerId variable does not seem to be set, please make sure you define one with the command 'set customerId'")

        # Add rg (resource group)
        elif mycmd[:2] == 'rg':
            if not self.variables['armToken']:
                print("You need to set an ARM token with the command 'set armtoken'")
                return False
            if not self.variables['subscriptionId']:
                print("You need to set a subscription ID with the command 'set subscriptionId'")
                return False
            if len(args) < 3:
                print("Please use the syntax 'add rg <name> <location>'. For example, 'add rg myresourcegroup westeurope'")
                return False
            createResourceGroup(self.variables['armToken'], self.variables['subscriptionId'], args[1], args[2], verbose=opts.verbose)

        # Whaaat?
        else:
            print ("Add command not recognized, please type 'help add' for information on this command")

    ##########
    # DELETE #
    ##########
    @cmd2.options([cmd2.make_option('-v', '--verbose', action="store_true", help="show REST API info")])
    def do_delete(self, line, opts=None):
        '''
        Deletes an existing object. Commands supported:
           delete customer
        '''
        args = line.split()
        if len(args) < 1:
            print("Not enough arguments provided, please type 'help delete' for information on this command")
            return False
        if not self.variables['cspToken']:
            print("No CSP token seems to be set, please make sure you define one with the command 'set token'")
        mycmd = args[0].lower()

        # Delete customer
        if mycmd[:3] == 'cus':
            if len(args) > 1:
                customerId = args[1]
                if isGuid(customerId):
                    if query_yes_no('Are you sure you want to delete customer ' + customerId, default="no"):
                        deleteCustomer(customerId, self.variables['cspToken'], opts.verbose)
                else:
                    print('%s does not seem to be a valid GUID format, trying it as customer name' % customerId)
                    customerName = customerId
                    customerId = getCustomerId(self.variables['cspToken'], customerName, opts.verbose)
                    if customerId and isGuid(customerId):
                        if query_yes_no('Are you sure you want to delete customer ' + customerId, default="no"):
                            deleteCustomer(customerId, self.variables['cspToken'], opts.verbose)
                    else:
                        print('No customer was found named %s' % customerName)
            elif self.variables['customerId']:
                if query_yes_no('Are you sure you want to delete customer ' + self.variables['customerId'], default="no"):
                    deleteCustomer(self.variables['customerId'], self.variables['cspToken'], opts.verbose)
            else:
                print("The customerId variable does not seem to be set, please make sure you define one with the command 'set customerId'")

        # Whaaat?
        else:
            print ("Delete command not recognized, please type 'help add' for information on this command")


    # Save variables to a JSON file
    def do_save(self, filename):
        '''
        Save the variable values to a file in JSON format. If no argument specified,
            saves to the current location
        Example: save mycsp.json
        '''
        args = filename.split()
        if len(args) < 1:
            print ("Please specify a file name")
        else:
            myfile = args[0]			
            saveDict(self.variables, myfile)
            # Update prompt with filename
            filename = os.path.basename(filename)
            fileshort = filename.split(".")[0]
            self.prompt = fileshort + "> "

    # Load variables from a JSON file
    def do_load(self, filename):
        '''
        Load the variable definitions from a file in JSON format (previously saved with the command 'save')
        Example: load mycsp.json
        '''
        if filename:
            try:
                with open(filename) as json_file:
                    # Instead of a simple assignment (that would override variables not existing in the file),
                    #   we assign variable per variable
                    loadDict = simplejson.load(json_file)
                    for variable in loadDict:
                        try:
                            self.variables[variable] = loadDict[variable]
                        except:
                            print("Error: could not load variable %s" % variable)
                            pass
            except:
                print ("Error loading data from file %s" % filename)
            # Update prompt with filename
            filename = os.path.basename(filename)
            fileshort = filename.split(".")[0]
            self.prompt = fileshort + "> "
        else:
            print ('Please specify a file name where to load the data from')

    def do_exit(self, *args):
        return True

    do_get = do_show  # "get" is a synonym for "show"
    do_new = do_add

def main():

    # Initiate cmd class
    c = CmdLineApp()
    c.cmdloop()


    # Old code, I might need it some day... Or maybe not?
    '''
    # Find out information
    tenantId = cspGetTenantId(token, customerName)
    customerId = cspGetCustomerId(token, customerName)
    

    # Get consumption per subscription for a given customer
    consumptionSummary = getConsumptionSummary(token, customerId)
    if consumptionSummary:
        print('CONSUMPTION SUMMARY FOR ' + customerName + ':')
        printList(consumptionSummary, [10, 45])

    # Set the subscription to the first Azure subs with consumption
    subscriptionId = consumptionSummary[0]['subscriptionId']

    # Get consumption by resource. Build a dictionary that gives additional info
    #   for each resource ID (or resource GUID, properly said)
    myDict = buildResourceDict(token, customerId, subscriptionId)
    # DEBUG DICTIONARY
    #printList (myDict, [50, 45, 50])
    resourceConsumption = getResourceConsumption(token, customerId, subscriptionId, myDict)
    if resourceConsumption:
        print('RESOURCE CONSUMPTION SUMMARY FOR ' + customerName + ', SUBSCRIPTION ID ' + subscriptionId + ':')
        printList(resourceConsumption, [10, 45, 20, 50])

    # Getting information out of the ARM API
    armTenantToken = armlogin(tenantId, appId, appSecret)
    armResourceGroups = getResourceGroups(armTenantToken, subscriptionId)
    if armResourceGroups:
        print('EXISTING RESOURCE GROUPS FOR ' + customerName + ', SUBSCRIPTION ID ' + subscriptionId + ':')
        printList(armResourceGroups)

    # Good bye
    print ("PRINTED RESULTS from customer " + customerName + ', tenant ID: ' + tenantId + ', Subscription ID: ' + subscriptionId)
    '''

if __name__ == '__main__': main()
