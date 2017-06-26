# This script demonstrates how to use functions from the cspcli module.
# In this case, csplogin and addCustomer functions are imported.
# The options must be specified from the command line.


from cspcli import addCustomer, csplogin
from optparse import OptionParser

def main():
    parser = OptionParser()
    parser.add_option("-a", "--appid", dest="appId",
                    help="Specify app ID to use for automation", metavar="APPID")
    parser.add_option("-s", "--appsecret", dest="appSecret",
                    help="Specify the app secret to use for automation", metavar="APPSECRET")
    parser.add_option("-t", "--csptenantid", dest="cspTenantId",
                    help="Specify the GUID for your CSP tenant", metavar="NAME")
    parser.add_option("-n", "--customername", dest="customerName",
                    help="Specify the name of the new customer to create", metavar="NAME")
    parser.add_option("-v", "--verbose",
                    action="store_true", dest="verbose", default=False,
                    help="Show the contents of the REST API calls")

    (options, args) = parser.parse_args()

    if options.appId and options.appSecret and options.cspTenantId and options.customerName:
        token = csplogin(options.cspTenantId, options.appId, options.appSecret, verbose=options.verbose)
        customerJson = addCustomer(options.customerName, token, verbose=options.verbose)
        if customerJson:
            try:
                print('Customer %s with GUID %s created' % (options.customerName, customerJson['id']))
            except:
                pass
    else:
        print("Error, please specify required options. Check them with the --help option")

if __name__ == '__main__': main()
