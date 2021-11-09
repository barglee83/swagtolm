# Python program to demonstrate
# Conversion of JSON data to
# dictionary
# Add support for Server URL to extract Domain Name and URL

  
# importing the module
import json,re,requests,xmltodict,sys,getopt

full_cmd_arguments = sys.argv

# Keep all but the first
argument_list = full_cmd_arguments[1:]

print(argument_list)

short_options = "hf:v"
long_options = ["help", "file=", "verbose"]

try:
    arguments, values = getopt.getopt(argument_list, short_options, long_options)
except getopt.error as err:
    # Output error, and return with an error code
    print (str(err))
    sys.exit(2)

file=""
# Evaluate given options
for current_argument, current_value in arguments:
    if current_argument in ("-v", "--verbose"):
        print ("Enabling verbose mode")
    elif current_argument in ("-h", "--help"):
        print ("Exmaple Usage: python swagtolm.py swaggerfile.json")
    elif current_argument in ("-f", "--file"):
        print (("File used is (%s)") % (current_value))
        file=current_value

if(file==""):
    print ("No File Provided")
    print ("Exmaple Usage: python swagtolm.py swaggerfile.json")
    exit()

# Opening JSON file with open(sys.argv[2],encoding='utf-8-sig', mode='r') as infile:
with open(file) as json_file:
    data = json.load(json_file)

    lminfo = {'lm': data['loadmaster']['lmip'], 'userpass': (data['loadmaster']['user']+":"+data['loadmaster']['pass'])}
    vsinfo = {'vsname': data['info']['title'], 'vsip': data['loadmaster']['vsip'], 'vsport': data['loadmaster']['vsport'], 'espdomain': "BARGLEELDAP",
              'allowedhosts': "ebanking.barglee.com", 'rsip': data['loadmaster']['realservers']}

    print(lminfo)
    print(vsinfo)

    uniqueControllerNameList = []
    for i in data['tags']:
        uniqueControllerNameList.append(i['name'])
    print(uniqueControllerNameList)
    # Create Sub Vs for each

    fullControllerNameList = []
    fullMethodList = []
    fullUrlList = []
    config = []

    #Find Base path for Each Tag e.g /account
    controllerDict={}
    for name in uniqueControllerNameList:
        match=0
        for url in (data['paths']):
            for method in (data['paths'][url]):
                if(data['paths'][url][method]['tags'][0]==name):
                    controllerDict["/"+url.rsplit('/')[1:][0]]=name
                    match=1
                    break
                if(match==1):
                    break
            if (match == 1):
                break
    print(controllerDict)

    regexdict=data['components'][0]['regexpatterns']



    for url in (data['paths']):
        a = url
        result=re.findall('\{.*?\}', url)
        print (result)
        if result:
            print("Needs Replaement String")
            for text in result:
                for regex in regexdict:
                    print("check if Regex found for ",text, "in", regex['name'])
                    if regex['name'] == text.replace('{','').replace('}',''):
                        print("Replacement is", regex['regex'].replace('$','').replace('^',''))
                        a=a.replace(text,regex['regex'].replace('$','').replace('^',''))
                        print("TEXT IS", a)
                        break
        else:
            print("Normal String")
            a=url

        for method in (data['paths'][url]):
            #Need array of dictionaries foreach url/method combo
            dict = {}
            dict['section']="/"+url.rsplit('/')[1:][0]
            dict['method']=method
            dict['url']=url
            dict['pattern']='/^'+re.sub('/','\/',a)+'$/'
            print("Pattern being added is",dict['pattern'])
            config.append(dict)

    #[{'name': 'Account', 'method': 'post', 'url': '/account/newpassword'}, {'name': 'Account', 'method': 'post', 'url': '/account/checkPassword'}, {'name': 'Account', 'method': 'get', 'url': '/account/roles'}, {'name': 'Account', 'method': 'put', 'url': '/account/culture/{cultureName}'}, {'name': 'Application', 'method': 'post', 'url': '/app/config'}, {'name': 'Currency', 'method': 'post', 'url': '/pms/(.*)/(.*)/xrate'}, {'name': 'Documents', 'method': 'post', 'url': '/documents/(.*)/(.*)/summary'}, {'name': 'Oauth', 'method': 'get', 'url': '/oauth2/token'}]
    print("config")
    print(json.dumps(config))

    #print(config)
    #exit()
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

