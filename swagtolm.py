# Python program to demonstrate
# Conversion of JSON data to
# dictionary
# Add support for Server URL to extract Domain Name and URL
# importing the module
#
#       1. Add checks that sections exist e.g. loadmaster and Vs config. Exit Gracefully if not there
#       2. Same for Parameters
#       3. Move Regex section to Parameters with pattern keyword. If not there use generic if these use regex defined.
#              "parameters": [
#                  {
#                      "name": "petId",
#                      "in": "path",
#                      "description": "ID of pet to update",
#                      "required": true,
#                      "type": "integer",
#                      "format": "int64"
#                      "pattern": '^\d{3}-\d{2}-\d{4}$'
#                  },

import json,re,requests,xmltodict,sys,getopt
import logging as log

# Pass in JSON Data and Extract info
def extractLmInfo(data):
    lminfo = {'lm': data['loadmaster']['lmip'],
              'userpass': (data['loadmaster']['user'] + ":" + data['loadmaster']['pass'])}
    log.info("LoadMaster Info: "+str(lminfo))
    return lminfo

def extractVsInfo(data):
    vsinfo = {'vsname': data['info']['title'], 'vsip': data['loadmaster']['vsip'],
              'vsport': data['loadmaster']['vsport'], 'espdomain': "BARGLEELDAP",
              'allowedhosts': "ebanking.barglee.com", 'rsip': data['loadmaster']['realservers']}
    log.info("Virtual Service Info: "+str(vsinfo))
    return vsinfo

def extractUniqueControllerList(data):
    uniqueControllerNameList = []
    for i in data['tags']:
        uniqueControllerNameList.append(i['name'])
    controllerDict = {}

    for name in uniqueControllerNameList:
        match = 0
        for url in (data['paths']):
            for method in (data['paths'][url]):
                if (data['paths'][url][method]['tags'][0] == name):
                    controllerDict["/" + url.rsplit('/')[1:][0]] = name
                    match = 1
                    break
                if (match == 1):
                    break
            if (match == 1):
                break
    log.info("Controller List"+str(controllerDict))
    return controllerDict

def main():
    #Parse User Input
    full_cmd_arguments = sys.argv
    argument_list = full_cmd_arguments[1:]
    short_options = "hf:v"
    long_options = ["help", "file=", "verbose"]
    try:
        arguments, values = getopt.getopt(argument_list, short_options, long_options)
    except getopt.error as err:
        # Output error, and return with an error code
        print (str(err))
        sys.exit(2)

    file=""
    verbose=0

    # Evaluate given options
    for current_argument, current_value in arguments:
        print(current_argument)
        if current_argument in ("-v", "--verbose"):
            print ("Enabling verbose+ mode")
            verbose=1
        elif current_argument in ("-h", "--help"):
            print ("Exmaple Usage: python swagtolm.py swaggerfile.json")
        elif current_argument in ("-f", "--file"):
            print (("File used is (%s)") % (current_value))
            file=current_value

    # Set Higher Debug Levels
    verbose = 2
    # verbose = 3

    if(verbose==1):
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.INFO)
    elif(verbose==2):
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.DEBUG)
    else:
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.WARNING)

    if(file==""):
        log.critical("Exiting, No File Provided")
        log.critical("Example Usage: python swagtolm.py swaggerfile.json")
        exit()

    # ----------------------------------------
    # Opening JSON file with open(sys.argv[2],encoding='utf-8-sig', mode='r') as infile:

    with open(file) as json_file:
        data = json.load(json_file)
        #lminfo = extractLmInfo(data)
        #vsinfo = extractVsInfo(data)
        controllerDict = extractUniqueControllerList(data)

        config = []
        regexdict=data['components'][0]['regexpatterns']
        ###log.info(type(data['components'][0]))
        for url in (data['paths']):
            for method in (data['paths'][url]):
                #Need array of dictionaries foreach url/method combo
                dict = {}
                dict['section']="/"+url.rsplit('/')[1:][0]
                dict['method']=method
                dict['url']=url
                # Check if Regex in Path
                a = url
                result = re.findall('\{.*?\}', url)
                if result:
                    log.info(str(result) + " Needs Replacement String")
                    #log.debug("Check for type in parameters")
                    #log.debug(data['paths'][url])
                    #log.debug(data['paths'][url][method]["parameters"][0])
                    #log.debug(data['paths'][url][method]["parameters"][0]["name"])
                    for text in result:
                    #     log.debug("check"+text)
                    #     log.debug("check"+re.sub('[{}]', '', text))
                    #     if (data['paths'][url][method]["parameters"][0]["name"] == re.sub('[{}]', '', text)):
                    #         log.debug("local definition found")
                    #         log.debug(data['paths'][url][method]["parameters"][0]["type"])
                    #         if(data['paths'][url][method]["parameters"][0]["type"]=="integer"):
                    #             log.debug("integer regex added")
                    #             a = a.replace(text,"([0-9]+([.][0-9]*)?|[.][0-9]+)")
                    #         elif(data['paths'][url][method]["parameters"][0]["type"]=="string"):
                    #             log.debug("string regex added")
                    #             a = a.replace(text, "REGEXFORSTRING")
                    #         elif(data['paths'][url][method]["parameters"][0]["type"]=="boolean"):
                    #             log.debug("string regex added")
                    #             a = a.replace(text, "REGEXFORBOOL")
                    #         continue
                        for regex in regexdict:
                            log.debug("check if Regex found for "+text+" in "+regex['name'])
                            if regex['name'] == text.replace('{','').replace('}',''):
                                log.debug("Replacement is"+regex['regex'].replace('$','').replace('^',''))
                                a=a.replace(text,regex['regex'].replace('$','').replace('^',''))
                                break
                # End URL Mapping Section
                dict['pattern']='/^'+re.sub('/','\/',a)+'$/'
                log.debug("Pattern being added is"+str(dict['pattern']))
                config.append(dict)



                # Check if Regex in Path
                #a = url
                #result=re.findall('\{.*?\}', url)
                #if result:
                #    log.info(str(result)+" Needs Replacement String")
                #    # Check if Locally Defined Substitution
                #    log.debug("Check for type in parameters")
                #    log.debug(data['paths'][url])
                #    for text in result:
                #        for regex in regexdict:
                #            log.debug("check if Regex found for "+text+" in "+regex['name'])
                #            if regex['name'] == text.replace('{','').replace('}',''):
                #                log.debug("Replacement is"+regex['regex'].replace('$','').replace('^',''))
                #                a=a.replace(text,regex['regex'].replace('$','').replace('^',''))
                #               break
                #End URL Mapping Section






        #print("config")
        log.info("config to Build"+str(json.dumps(config)))
        exit()

    #============ Create Config

        sectionlist = []
        for i in config:
            if i.get('section') not in sectionlist:
                sectionlist.append(i.get('section'))
        print("Unique Sections", sectionlist)


        methodlist = []
        for i in config:
            if i.get('method') not in methodlist:
                methodlist.append(i.get('method') )
        print("Unique Methods",methodlist)

        url = "https://" + lminfo.get('userpass') + "@" + lminfo.get('lm') + "/access/addvs?vs=" + vsinfo.get('vsip') + "&port=" + vsinfo.get('vsport') + "&prot=tcp&nickname=" + vsinfo.get('vsname') + "&SSLAcceleration=1" +"&EspEnabled=1&InputAuthMode=0&AllowedHosts=" + vsinfo.get('allowedhosts') +"&AllowedDirectories=/*"
        response = requests.get(url)
        print(url)
        print(response.status_code)


        for i in sectionlist:
            url = "https://" + lminfo.get('userpass') + "@" + lminfo.get('lm') + "/access/modvs?vs=" + vsinfo.get('vsip') + "&port=" + vsinfo.get('vsport') + "&prot=tcp&createsubvs="
            response = requests.get(url)
            print(url)
            print(response.status_code)

        #      __                  -subvs
        #     |vs|-ssl+esp+delegate-subvs
        #      ==

        subvslist = []
        subvsrsidlist = []

        url = "https://" + lminfo.get('userpass') + "@" + lminfo.get('lm') + "/access/showvs?vs=" + vsinfo.get(
            'vsip') + "&port=" + vsinfo.get('vsport') + "&prot=tcp"
        response = requests.get(url)
        print(url)
        print(response.status_code)
        obj = xmltodict.parse(response.text)
        for index, v in enumerate((obj["Response"]["Success"]["Data"]["SubVS"])):
            print(v)
            print("Append", v.get('VSIndex'))
            subvslist.append(v.get('VSIndex'))
            subvsrsidlist.append(v.get('RsIndex'))

        # This gives us a list of VSID and RSIDs for the SubVS's

        print("sectionlist is", sectionlist)
        print("methodlist is", methodlist)
        print("subvslist is", subvslist)


        for idx, i in enumerate(sectionlist):
            print("IDX",idx)
            pat='/^'+re.sub('/','\/',i)+'.*/'
            print("Vars",i,controllerDict[i])
            url = "https://" + lminfo.get('userpass') + "@" + lminfo.get('lm') + "/access/addrule?name=" + controllerDict[i] + "&matchtype=regex&pattern=" + pat + "&nocase=1"
            response = requests.get(url)
            print(url)
            print(response.status_code)
            url = "https://" + lminfo.get('userpass') + "@" + lminfo.get('lm') + "/access/modvs?vs=" + subvslist[idx] + "&nickname=" + controllerDict[i]
            response = requests.get(url)
            print(url)
            print(response.status_code)
            url = "https://" + lminfo.get('userpass') + "@" + lminfo.get('lm') + "/access/addrsrule?vs=" + vsinfo.get('vsip') + "&port=" + vsinfo.get('vsport') + "&prot=tcp&rs=!" + subvsrsidlist[idx] + "&rule="+controllerDict[i]
            response = requests.get(url)
            print(url)
            print(response.status_code)


        #      __                                       -steer1--subvs
        #     |vs|-ssl+esp+formbased+espdomain+steering -steer2--subvs
        #      ==                                       -steer3--subvs

        flagIndex = 1;
        secondRuleNameList = []

        for i in methodlist:
            url = "https://" + lminfo.get('userpass') + "@" + lminfo.get(
                'lm') + "/access/addrule?name=METHOD_" + i + "&matchtype=regex&header=method&pattern=" + i + "&setonmatch=" + f'{flagIndex}'
            response = requests.get(url)
            print(url)
            print(response.status_code)

            flagIndex += 1
        #      __                                       -steer1--subvs--
        #     |vs|-ssl+esp+formbased+espdomain+steering -steer2--subvs--
        #      ==                                       -steer3--subvs--
        #
        #       Second Rules Created with Flags Setters

        # Name Each SubVS
        cnt=0
        for i in subvslist:
            for mtd in methodlist:
                url= "https://"+lminfo.get('userpass')+"@"+lminfo.get('lm')+"/access/addprerule?vs="+i+"&rule=METHOD_" + mtd
                response = requests.get(url)
                print(url)
                print(response.status_code)


        #      __                                       -steer1--subvs-flagrules-
        #     |vs|-ssl+esp+formbased+espdomain+steering -steer2--subvs-flagrules-
        #      ==                                       -steer3--subvs-flagrules-
        #
        #       IP ACLs Created
            for rs in vsinfo.get('rsip'):
                url= ("https://"+lminfo.get('userpass')+"@"+lminfo.get('lm')+"/access/addrs?vs="+i+"&rs="+rs+"&rsport=80")
                response = requests.get(url)
                print(url)
                print(response.status_code)

        #      __                                       -steer1--subvs-ALLACLs-RS1,RS2
        #     |vs|-ssl+esp+formbased+espdomain+steering -steer2--subvs-ALLACLs-RS1,RS2
        #      ==                                       -steer3--subvs-ALLACLs-RS1,RS2

        idx=1
        #Go through Each line of File
        for rule in config:
            print(rule)
            a=rule.get('url')
            #IF URL includes {} Replace with Regex
            #result = re.search(r"\{([A-Za-z0-9_]+)\}", a)
            #if result:
            #    print("found regex",result)#Replace with Reg Ex
            #    for regex in regexdict:
            #        if regex['name'] == result.group(1):
            #            pattern = r'[^$]'
            #            replacement = re.sub(pattern, '', regex['regex'])
            #            print(replacement)
            #else:
            #    print("no found regex")
            #    #Do Nothing

            subvsid = subvslist[sectionlist.index(rule.get("section"))]
            print("SubVSID is",subvsid)
            flag=methodlist.index(rule.get('method'))+1
            url = "https://" + lminfo.get('userpass') + "@" + lminfo.get('lm') + "/access/addrule?name=apiurl" + re.sub(r'\W+', '', rule.get('url')) + f'{idx}'+"&matchtype=regex&pattern=" + rule.get('pattern') + "&onlyonflag=" + f'{flag}' + "&nocase=1"
            response = requests.get(url)
            print(url)
            print(response.status_code)
            for rsip in vsinfo.get('rsip'):
                url = "https://" + lminfo.get('userpass') + "@" + lminfo.get('lm') + "/access/addrsrule?vs="+ subvsid +"&rs="+rsip+"&rsport=80&rule=apiurl"+ re.sub(r'\W+', '', rule.get('url'))+ f'{idx}'
                response = requests.get(url)
                print(url)
                print(response.status_code)
            idx+=1




        #exit()




               # fullControllerNameList.append(data['paths'][url][method]['tags'][0])
               # fullMethodList.append(method)
               # fullUrlList.append(url)met
        #print(fullControllerNameList)
        #print(fullMethodList)
        #print(fullUrlList)




        # Create Sub Vs for each



        #secondlist = []
        #for i in config:
        #    a = i.get(csv_headings[1])
        #    if a not in secondlist:
        #        secondlist.append(a)
        #print("LIST2", secondlist)



        # Print the data of dictionary
        print("Create the following VS's")
        #for domain in data['servers']:

            # Get Allowed Domain Here.
            # Get Base URL here.
            # If contains http get X.X.X
            #if(domain['url'].find("http")==-1):
            #    print("Domain BLANK")
            #    print("URL", domain['url'])
            #else:
            #    print("DOMAIN", url[url.find("://") + 1:url.find("/")])
            #    print("URL", domain['url'])
        for i in (data['tags']):
            print(i['name'])


        print("Create the following URL Rules")
        #print(data['paths']["/pet"])
        for url in (data['paths']):
            for method in (data['paths'][url]):
                print (data['paths'][url][method]['tags'][0],method, url)
                if(url.find("{")==-1):
                    print ("NONE")
                else:
                    print(url[url.find("{") + 1:url.find("}")])
                    #Find Replacement


                print("----")


                #for attribute in (data['paths'][url][method]):

                    #print(url,method,tag['tag'])
                   # print(attribute)
                   # print(type(attribute))

if __name__ == '__main__':
    main()