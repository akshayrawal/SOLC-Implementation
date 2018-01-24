import json

files = ['licensedata.json','licensefound.json','policy.json']

with open('licensedata.json', 'r', encoding = "utf-8") as f:
        licensedata =  json.load(f)

with open('licensefound.json', 'r', encoding = "utf-8") as f:
        licensefound =  json.load(f)

with open('policy.json', 'r', encoding = "utf-8") as f:
        policy =  json.load(f)

deny_list = []
flag_list = []
approve_list = []
deny_attribute = []


print("Getting user preferences...")

for i in range(0,len(policy)):

    user_policy = policy[i]["policy type"]
    policy_action = policy[i]["action"]

    if (user_policy == "license" or user_policy == "library") and policy_action == "deny":
        print(policy[i]["action"] , policy[i]["policy type"] , " : " , policy[i]["name"])
        deny_list.append(policy[i]["name"])
        
    if user_policy == "attribute" and policy_action == "deny":
        print(policy[i]["action"] , policy[i]["policy type"] , " : " , policy[i]["name"]['value'] , policy[i]["name"]['attribute'])
        deny_attribute.append(policy[i]["name"])

    if user_policy == "attribute" and policy_action == "flag":
        attribute = (policy[i]["name"])
        print(policy[i]["action"] , policy[i]["policy type"] , " : " , policy[i]["name"]['value'] , policy[i]["name"]['attribute'])

    elif policy_action == "approve":
        print(policy[i]["action"] , policy[i]["policy type"] , " : " , policy[i]["name"])
        approve_list.append(policy[i]["name"])


#get attributes for licenses
def remove_duplicates(t):
    s = []
    for i in t:
       if i not in s:
          s.append(i)
    return s


license_found = []
library_found = []
Permissions = []
Restrictions = []
Obligations = []
scan_messages = {"libraries found" : [],
                "licenses found" : [],
                "denied license" : [],
                "denied library" : [],
                "denied attributes" : [],
                "flagged license" : [],
                "flagged library" : [],
                "flagged attributes" : []}


for i in range(1,len(licensefound)):
    
    if (licensefound[i]["license"]) in deny_list:
        scan_messages["denied license"].append("Denied License detected, You chose not to include the license: " + str(licensefound[i]["license"]))
    if (licensefound[i]["library"]) in deny_list:
        scan_messages["denied library"].append("Denied Library detected, You chose not to include the library: " + str(licensefound[i]["library"]))
        
    scan_messages["licenses found"].append(licensefound[i]["license"])
    scan_messages["libraries found"].append(licensefound[i]["library"])

    for y in range(0,len(licensedata)):

        if licensefound[i]["license"] in licensedata[y]["name"]:
            
            for z in range(len(deny_attribute)):
                if (deny_attribute[z]['attribute'] in (licensedata[y]["permissions"])) and (deny_attribute[z]['value'] == "can"):
                    scan_messages["denied attributes"].append("Denied Attribute detected, You chose not to include licenses where you can " + str(deny_attribute[z]['attribute']))
                    continue
                if (deny_attribute[z]['attribute'] in (licensedata[y]["restrictions"])) and (deny_attribute[z]['value'] == "cannot"):
                    scan_messages["denied attributes"].append("Denied Attribute detected, You chose not to include licenses where you cannot " + str(deny_attribute[z]['attribute']))
                    continue
                if (deny_attribute[z]['attribute'] in (licensedata[y]["obligations"])) and (deny_attribute[z]['value'] == "must"):
                    scan_messages["denied attributes"].append("Denied Attribute detected, You chose not to include licenses where you must " + str(deny_attribute[z]['attribute']))
                    continue
                
            for permissions_name in range (len(licensedata[y]["permissions"])):
                Permissions.append(licensedata[y]["permissions"][permissions_name])

            for restrictions_name in range (len(licensedata[y]["restrictions"])):               
                Restrictions.append(licensedata[y]["restrictions"][restrictions_name])
                
            for obligations_name in range (len(licensedata[y]["obligations"])):               
                Obligations.append(licensedata[y]["obligations"][obligations_name])


print("libraries found\n" ,scan_messages["libraries found"], "\n") 
print("licenses found\n" ,scan_messages["licenses found"], "\n")
print("denied library\n" ,scan_messages["denied library"], "\n")
print("denied license\n" ,scan_messages["denied license"], "\n")
print("denied attributes\n" , scan_messages["denied attributes"], "\n")

print("overall attributes for the current code:")

print(  " Permissions: " , remove_duplicates(Permissions) , "\n" ,
        "Restrictions: " , remove_duplicates(Restrictions), "\n" ,
        "Obligations: " , remove_duplicates(Obligations)  )
