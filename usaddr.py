#!/usr/bin/python

# Amazon Lambda function to (a) parse and format US addresses into individual address
# components and assemble them into useful composite elements and (b) run the address
# through the USPS address correction tool, resulting in an address that the USPS
# agrees actually exists.

# event fields:
#
#   'addr' : the address to be munged
#   'parse' : if 'yes', run the address through the USADDRESS parser.
#   'validate' : if 'yes', run the address through the USPS tool.
#
# if parsing fails, an attempt will be made to fix the problem by reordering the input lines.
# if validation fails and parsing was not done, validation will be retried after parsing.
#
# Note that since the lambda event has to stay active while calling USPS, you'll get
# charged for a second or two of CPU when validating, vs. the minimum 100msec
# for just doing the parsing.

# Output:
#
# An OrderedDict of:
#
#    The individual address element fields (USADDRESS)
#    Parsed_XXX fields : composite USADDRESS fields that are more useful (ie: Parsed_AddressNumber
#       will have the address line. See the breakfields list for more details.
#    Parsed_Address_Complete : a complete, 4 or 5 line address
#    Validated_Address1,_Address2,_City,_State,_Zip5,_Zip4,_Zipcode fields: individual address
#       fields as processed by USPS
#    Validated_Address_Complete: a complete 4 or 5 line validated address
#
# If you don't do parsing, you won't get the Parsed_ fields; likewise for validation
#
# Lambda will return the OrderedDict as JSON, of course

# Based on USADDRESS by the Atlanta Journal Constitution, released under the MIT license.
# This code is released under the same license.

# Created by a infinite number of monkeys under the loose direction of Robert Woodhead,
# trebor@animeigo.com

import usaddress
import urllib
import urllib2
import re
import collections


# Placeholder exception

class USPSException(Exception):
    pass


# Lambda event handler

def lambda_handler(event, context):
    if event is None:
        return {'Error': 'No lambda event provided - this should never happen!'}

    if 'addr' not in event:
        return {'Error': 'No addr parameter provided'}

    if (event.get('parse') != 'yes') and (event.get('validate') != 'yes'):
        return {'Error': 'No processing options specified -- nothing to do here'}

    # Clean up the address

    addr = event['addr'].replace('\t', ' ').replace('\n', '\r').strip()

    # Initialize results

    c = collections.OrderedDict()

    # Optional usaddress parsing

    if event.get('parse') == 'yes':

        try:

            # Parse the address

            c = usaddress.tag(addr)[0]

            # Go down through the returned components, collecting sets of parts into more
            # useful address components

            l = []

            # We collect fields until we hit one of these breakfields.

            breakfields = [
                'Recipient',
                'BuildingName',
                'LandmarkName',
                'CornerOf',
                'USPSBoxType',
                'AddressNumber',
                'AddressNumberPrefix',
                'PlaceName',
                'StateName',
                'ZipCode',
                'CountryName'
            ]

            # Some breakfields require that other breakfields be henceforth ignored

            multikill = {
                'AddressNumberPrefix': ['AddressNumber']
            }

            parsed = []
            cfield = ''

            # Now run through the fields and assemble the composite fields

            # Since I am adding items to c inside the loop, I first make a list of the
            # item-value pairs. I don't need to do this in 2.7 but am future-proofing
            # in case this gets migrated to 3.x

            citems = list(c.items())

            for k, v in citems:

                if cfield == '':
                    cfield = k

                if k in breakfields:

                    breakfields.remove(k)

                    if k in multikill:
                        for mk in multikill[k]:
                            if mk in breakfields:
                                breakfields.remove(mk)

                    l = [i for i in l if i]

                    if l:
                        l = ' '.join(l)
                        parsed.append(l)
                        c['Parsed_' + cfield] = l
                        cfield = k

                    l = [v]

                else:

                    l.append(v)

            # Add the last field

            l = [i for i in l if i]

            if l:
                l = ' '.join(l)
                parsed.append(l)
                c['Parsed_' + cfield] = l

            # Add combined version of address

            c['Parsed_Address_Complete'] = '\n'.join(parsed)

            # Do a little cleanup, just to be nice

            for k in c:
                c[k] = c[k].strip()

            # Update addr

            addr = '\r'.join(parsed)

        except usaddress.RepeatedLabelError:

            # If we cannot parse the address, before giving up, we try again but swap the first
            # and second line of the address; this will often handle situations where the
            # company name is on line 2, instead of line 1 where the usaddress parser expects
            # it to be

            if 'pass2' in event:

                return {'Error': 'Cannot parse address'}

            else:

                event['pass2'] = True
                addr = addr.split('\r')
                line1 = addr[0]
                addr[0] = addr[1]
                addr[1] = line1
                event['addr'] = '\r'.join(addr)
                return lambda_handler(event, context)

    # Optional USPS address correction - it will, by the way, usually end up putting the
    # company name, if any, in Address2, so that's where we present that field if the
    # usaddress parser finds it.

    if event.get('validate') == 'yes':

        try:

            # Call USPS tool to validate address; we should have either a 4 or 5 line complete address,
            # but also try to handle more limited cases, by making educated guesses about what info
            # we got. Also it turns out that the USPS tool is more forgiving than it lets on...

            a = [l for l in addr.split('\r') if l != '']

            if len(a) < 2:

                c['Error'] = '4 or 5 line address preferred for validation (addr1, [addr2], city, state, zip on separate lines)'
                return c

            elif len(a) == 2:

                if '0123456789'.find(a[1][0]) != -1:
                    a = [a[0], '', '', '', a[1]]  # address, zip
                else:
                    a = [a[0], '', a[1], '', '']  # address, city

            elif len(a) == 3:

                if '0123456789'.find(a[2][0]) != -1:
                    if len(a[1]) != 2:
                        a = [a[0], '', a[1], '', a[2]]  # address, city, zip
                    else:
                        a = [a[0], '', '', a[1], a[2]]  # address, state, zip
                else:
                    a = [a[0], '', a[1], a[2], '']  # address, city, state

            elif len(a) == 4:

                a = [a[0], '', a[1], a[2], a[3]]  # address (1-line), city, state, zip

            elif len(a) > 5:

                a = a[0:5]  # too many lines, truncate

            # Create request

            a = [urllib.quote(l) for l in a]

            r = urllib2.Request(
                    'https://tools.usps.com/go/ZipLookupResultsAction!input.action?resultMode=0' +
                    '&companyName=' + '&address1=' + a[0] + '&address2=' + a[1] +
                    '&city=' + a[2] + '&state=' + a[3] +
                    '&urbanCode=&postalCode=&zip=' + a[4]
            )

            # USPS and other sites get cranky unless they see a user agent that looks like a browser

            r.add_header('User-Agent', 'Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11')

            # Get the result and strip out all the formatting

            u = urllib2.urlopen(r, timeout=10).read().replace('\t', '').replace('\r', '').replace('\n', '')

            # Use GREP-fu to extract fields from HTML

            e = re.compile(
                    '<div id="results">(.*?)<p class="std-address(.*?)' +
                    '<span class="address1(.*?)>(?P<Validated_Address1>.*?)<(.*?)' +
                    '(<span class="address2 range">(?P<Validated_Address2>.*?)<(.*?))?' +
                    '<span class="city(.*?)>(?P<Validated_City>.*?)<(.*?)' +
                    '<span class="state(.*?)>(?P<Validated_State>.*?)<(.*?)' +
                    '<span class="zip(.*?)>(?P<Validated_Zip5>.*?)<(.*?)' +
                    '<span class="zip4(.*?)>(?P<Validated_Zip4>.*?)<')

            m = e.search(u)

            # If our GREP-fu is not strong enough, then if we didn't try parsing the address, then
            # try doing that; otherwise, admit defeat!

            if not m:
                if event.get('parse') != 'yes':
                    event['parse'] = 'yes'
                    return lambda_handler(event, context)
                else:
                    raise USPSException

            # Otherwise, get the extracted fields and add them to the result

            fields = m.groupdict()

            # fields['Validated_Address2'] will be None if the optional field did not match.
            # However, I am paranoid, so I'll assume the key might not get set somehow

            if ('Validated_Address2' not in fields) or (not fields['Validated_Address2']):
                fields['Validated_Address2'] = ''

            # Do a little cleanup, just to be nice (and because USPS delivers! trailing spaces that is...)

            for k in fields:
                fields[k] = fields[k].strip()

            # Add to results in a nice order

            c['Validated_Address1'] = fields['Validated_Address1']
            c['Validated_Address2'] = fields['Validated_Address2']
            c['Validated_City'] = fields['Validated_City']
            c['Validated_State'] = fields['Validated_State']
            c['Validated_Zip5'] = fields['Validated_Zip5']
            c['Validated_Zip4'] = fields['Validated_Zip4']

            # Add a few final result fields

            c['Validated_ZipCode'] = c['Validated_Zip5'] + '-' + c['Validated_Zip4']

            c['Validated_Address_Complete'] = c['Validated_Address1'] + '\n' + \
                (c['Validated_Address2'] + '\n' if c['Validated_Address2'] != '' else '') + \
                c['Validated_City'] + '\n' + c['Validated_State'] + '\n' + c['Validated_ZipCode']

        except urllib2.HTTPError as e:

            c['Error'] = 'Validation HTTPS Error: ' + e.reason + ' Code: ' + e.code

        except urllib2.URLError as e:

            c['Error'] = 'Validation HTTPS Error: ' + e.reason

        except IOError as e:

            c['Error'] = 'Validation HTTPS Error: ' + e.message

        except USPSException:

            c['Error'] = 'Unable to parse USPS HTML'
            c['Error-HTML'] = u     # u will always be set before this exception can occur

    return c


# main is unit test code -- will never get called by Amazon lambda

if __name__ == '__main__':
    print lambda_handler(None, None)
    print lambda_handler({'derf': 'derf'}, {})
    print lambda_handler({'addr': '1 beold hahrafrar', 'parse': 'yes'}, {})
    print lambda_handler({'addr': '6810 Finian Drive\r\rWilmington\r\n\rNC 28409\rUSA'}, {})
    print lambda_handler({'addr': '6810 Finian Drive\r\rWilmington\r\n\rNC 28409\rUSA', 'parse': 'yes'}, {})
    print lambda_handler({'addr': 'PO BOX 007\rWILLOW AK 99688-0190', 'parse': 'no', 'validate': 'yes'}, {})
    print lambda_handler({'addr': '741 SUNSET AVE STE A\rLOBBY, DEPARTMENT OF HEALTH\rHONOLULU, HI 96816',
                          'parse': 'yes', 'validate': 'yes'}, {})
    print lambda_handler({'addr': '6810 Finian Drive\r28409', 'validate': 'yes'}, {})
    print lambda_handler({'addr': '6810 Finian Drive\rWilmington\rNC', 'validate': 'yes'}, {})
    print lambda_handler({'addr': '6810 Finian Drive\rWilmington\r28409', 'validate': 'yes'}, {})
