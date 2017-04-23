import time, hashlib, requests, urllib

class HackEx():
    def __init__(self):
        self.headers = {"User-Agent":"Hack Ex/1.0.2 (iPhone; iOS 8.2; Scale/2.00)"}
        self.other_data = {"software_type_ids":{"Firewall":"1","Bypasser":"2","Cracker":"3","Encryptor":"4","Antivirus":"5","Spam":"6","Spyware":"7"}}
    
    def make_sigs(self,params={}):
        out = {}
        now = str(int(time.time()*1000))
        params["sig2"] = now
        keys = sorted(params,key=lambda obj:str(obj).lower())[::-1]
        string = '1101101101'
        for key in keys:
            string += str(key) + str(params[key])
            out[key] = params[key]

        secret = "WqZnwjpaVZNvWDpJhqHCHhWtNfu86CkmtCAVErbQO"
        sha = hashlib.sha1()
        sha.update(string+secret)
        out["sig"] = sha.hexdigest()
        return out

    def get_req(self,url,params={}):
        params = self.make_sigs(params)
        html_formatted = urllib.urlencode(params)
        url = url+"?"+html_formatted
        r = requests.get(url,headers=self.headers)
        return r.json()

    def post_req(self,url,params={}):
        params = self.make_sigs(params)
        r = requests.post(url,headers=self.headers,data=params)
        return r.json()

    def login(self,email,password):
        login = self.post_req("https://api.hackex.net/v5/auth",{"email":email,"password":password})
        self.other_data["username"] = login["user"]["username"]
        self.other_data["level"] = login["user"]["level"]
        self.other_data["ip"] = login["user"]["ip"]
        self.other_data["id"] = login["user"]["id"]
        self.headers["X-API-KEY"] = login["user"]["auth_token"]

        data = self.get_req("http://api.hackex.net/v5/user_victim",{"victim_user_id":self.other_data["id"]})
        software = data["user_software"]
        softwares = {}
        for x in software:
            softwares[x["name"]] = x
        software_types = ["Firewall","Bypasser","Antivirus","Spyware","Firewall","Password Encryptor","Password Cracker","Spam","Notepad"]
        for x in software_types:
            try:
                x = softwares[x]
            except:
                softwares[x] = {"software_id":"0"}
        self.other_data["spam_id"] = softwares["Spam"]["software_id"]
        self.other_data["bypasser_id"] = softwares["Bypasser"]["software_id"]
        self.other_data["cracker_id"] = softwares["Password Cracker"]["software_id"]

    def recon(self,victim_id,do_process=False):
        data = self.get_req("http://api.hackex.net/v5/user_victim",{"victim_user_id":str(victim_id)})
        device = data["user_device"]["name"]
        network = data["user_network"]["name"]
        bank_data = data["user_bank"]
        user_data = data["user"]
        software = data["user_software"]
        softwares = {}
        for x in software:
            softwares[x["name"]] = x

        print "Username:",user_data["username"]
        print "IP:",user_data["ip"]
        print "ID:",user_data["id"]
        print "Created at:\t",user_data["created_at"]
        print "\nOverclocks:\t",user_data["overclocks"]+"\tLevel:\t",user_data["level"]
        print "Reputation:\t",user_data["reputation"]+"\tScore:",int(user_data["level"])*int(user_data["reputation"])
        print "\nChecking:\t",bank_data["checking"]+"\tSavings:",bank_data["savings"]

        #Apps start here
        software_types = ["Firewall","Bypasser","Antivirus","Spyware","Firewall","Password Encryptor","Password Cracker","Spam","Notepad"]
        for x in software_types:
            try:
                x = softwares[x]
            except:
                softwares[x] = {"software_level":"0"}
        print "\nFirewall:\t",softwares["Firewall"]["software_level"]+"\tEncryptor:\t",softwares["Password Encryptor"]["software_level"]
        print "Bypasser:\t",softwares["Bypasser"]["software_level"]+"\tCracker:\t",softwares["Password Cracker"]["software_level"]
        print "Antivirus:\t",softwares["Antivirus"]["software_level"]+"\tSpam:\t\t",softwares["Spam"]["software_level"]
        print "Spyware:\t",softwares["Spyware"]["software_level"]+"\tNotepad:\t",softwares["Notepad"]["software_level"]
        print "\nNetwork:\t",network+"\tDevice:\t\t",device,"\n\n"
        if do_process:
            print "Processes\n"

            #Processes here
            for process in data["user_processes"]:
                if len(process["ip"]) < 11:
                    process["ip"] += "\t"
                ptype = ["","Bypassing","Cracking","Downloading","Uploading"]
                ptype = ptype[int(process["process_type_id"])]
                status = ["","In Progress","Finished!","Failed!\t"]
                status = status[int(process["status"])]
                print "IP: ",process["ip"]+"\t",ptype+"\t",status+"\tID: ",process["id"]
    def self_recon(self,do_process=False):
        self.recon(self.other_data["id"],do_process)
        
    def mass_delete(self,kill=False,ptype=None):
        if ptype == None:
            ptype = raw_input("Which type of process would you like to delete?\n1) Bypass\n2) Crack\n3) Download\n4)Upload\nEnter corresponding number... ")
        processes = self.get_req("http://api.hackex.net/v5/user_victim",{"victim_user_id":self.other_data["id"]})["user_processes"]
        to_del = []
        for process in processes:
            if (process["process_type_id"] == ptype) and ((process["status"] != 1) or (kill == True)):
                #self.post_req("https://api.hackex.net/v5/process_delete",params={"process_id":process["id"]})
                to_del.append(process["id"])
                print "Process deleted!"

        #print to_del
        print "Processes will be deleted in 3 seconds."
        print "Press CTRL+C to cancel."
        time.sleep(5)
        self.post_req("https://api.hackex.net/v5/processes_delete",params={"process_ids":"|".join(to_del)})
        print "\nAll processes deleted!"
    def kill_id(self,process_id):
        self.post_req("https://api.hackex.net/v5/process_delete",params={"process_id":process_id})
        
    def advanced_scan(self,min_users=5,min_level=0,max_firewall=-1,max_encrypter=-1,min_money=0):
        found = []
        try:
            while len(found) < min_users:
                users = self.get_req("https://api.hackex.net/v5/users_random",params={"count":"5"})["users"]
                for user in users:
                    if int(user["level"]) >= min_level:
                        #map software
                        data = self.get_req("http://api.hackex.net/v5/user_victim",{"victim_user_id":user["id"]})
                        software = data["user_software"]
                        softwares = {}
                        for x in software:
                            softwares[x["name"]] = x
                        software_types = ["Firewall","Bypasser","Antivirus","Spyware","Firewall","Password Encryptor","Password Cracker","Spam","Notepad"]

                        for x in software_types:
                            try:
                                x = softwares[x]
                            except:
                                softwares[x] = {"software_level":"0"}
                        if max_firewall == -1:
                            if max_encrypter == -1:
                                money = int(data["user_bank"]["checking"])
                                if money >= min_money:
                                    found.append({"user":user,"money":money,"softwares":softwares})
                                    print "Found a user!"
                            elif int(softwares["Password Encryptor"]["software_level"]) <= max_encrypter:
                                money = int(data["user_bank"]["checking"])
                                if money >= min_money:
                                    found.append({"user":user,"money":money,"softwares":softwares})
                                    print "Found a user!"
                        elif int(softwares["Firewall"]["software_level"]) <= max_firewall:
                            if max_encrypter == -1:
                                money = int(data["user_bank"]["checking"])
                                if money >= min_money:
                                    found.append({"user":user,"money":money,"softwares":softwares})
                                    print "Found a user!"
                            elif int(softwares["Password Encryptor"]["software_level"]) <= max_encrypter:
                                money = int(data["user_bank"]["checking"])
                                if money >= min_money:
                                    found.append({"user":user,"money":money,"softwares":softwares})
                                    print "Found a user!"
        except KeyboardInterrupt:
            pass
        for user in found:
            print "Username:\t",user["user"]["username"]+"\tLevel:\t",user["user"]["level"]
            print "ID: ",user["user"]["id"]+"\tIP: ",user["user"]["ip"]
            print "Firewall:\t",user["softwares"]["Firewall"]["software_level"]+"\tEncryptor:\t",user["softwares"]["Password Encryptor"]["software_level"]
            print "Checking:\t",user["money"]
            print ""
            
    def send_spam(self,victim_id,level):
        spam = self.post_req("https://api.hackex.net/v5/process",params={"victim_user_id":str(victim_id),"process_type_id":4,"software_id":self.other_data["spam_id"],"software_level":str(level)})
        while not spam["success"]:
            spam = self.post_req("https://api.hackex.net/v5/process",params={"victim_user_id":str(victim_id),"process_type_id":4,"software_id":self.other_data["spam_id"],"software_level":str(level)})
        print "Upload started!"
        
    def lookup_ip(self,ip):
        user = self.get_req("https://api.hackex.net/v5/user",params={"process_type_id":"1","user_ip":ip})
        if user["success"]:
            print "Username: ",user["user"]["username"]
            print "Level: ",user["user"]["level"]
            print "ID: ",user["user"]["id"]
        else:
            print "User not found!"

    def spam_cascade(self,starting_level,number,targets=[],purge=False):
        if purge:
            self.mass_delete(True,4)
        spam = []
        if targets == []:
            while len(targets) < number:
                users = self.get_req("https://api.hackex.net/v5/users_random",params={"count":"5"})["users"]
                for user in users:
                    if user not in targets:
                        targets.append(user)
                        print "Done user",targets.index(user["id"])+1,"of",number

        time = (starting_level**3)*4
        for user in targets:
            spam.append(int(((time/(len(spam)+1))/4)**0.3333333333333333))

        #print "The following spams will be uploaded:"
        #for x in spam:
        #    print "Level",x

        for x in range(0,len(targets)):
            print "Uploading spam",x+1,"of",len(targets)
            self.send_spam(targets[x]["id"],spam[x])
        print "\n\n----------------------------------------------------------------"
        print "All spam uploading!!!"
        print "----------------------------------------------------------------"

    def read_log(self,victim_id,out=False):
        log = self.get_req("http://api.hackex.net/v5/user_victim",{"victim_user_id":str(victim_id)})["user_log"]
        #print "Last Updated:",log["last_updated"]
        x = "\n".join("\n".join(log["text"].split("&lt;br/&gt;")).split("&lt;br&gt;"))
        if not out:
            print "Last Updated:",log["last_updated"]
            print x
        else:
            return x

    def append_log(self,victim_id,text=None):
        begin_id = self.start_bypass(victim_id)
        log = self.get_req("http://api.hackex.net/v5/user_victim",{"victim_user_id":str(victim_id)})["user_log"]
        log = "\n".join("\n".join(log["text"].split("&lt;br/&gt;")).split("&lt;br&gt;"))
        if text == None:
            text = "\n".join(raw_input("Enter log text...\n").split("\\n"))
        text = "&lt;br/&gt;".join(text.split("\n"))
        log = text+log
        log = log[:4000]
        self.post_req("https://api.hackex.net/v5/victim_user_log",{"victim_user_id":str(victim_id),"text":log})
        self.kill_id(begin_id)

    def replace_log(self,victim_id,text=None):
        begin_id = self.start_bypass(victim_id)
        if text == None:
            text = "\n".join(raw_input("Enter log text...\n").split("\\n"))
        text = "&lt;br/&gt;".join(text.split("\n"))
        text = text[:4000]
        self.post_req("https://api.hackex.net/v5/victim_user_log",{"victim_user_id":str(victim_id),"text":text})
        self.kill_id(begin_id)

    def start_bypass(self,victim_id):
        new = self.post_req("https://api.hackex.net/v5/process",params={"victim_user_id":str(victim_id),"process_type_id":1,"software_id":self.other_data["bypasser_id"]})
        print "Bypass started!"
        try:
            return new["user_processes"][0]["id"]
        except:
            print new

    def start_crack(self,victim_id):
        new = self.post_req("https://api.hackex.net/v5/process",params={"victim_user_id":str(victim_id),"process_type_id":2,"software_id":self.other_data["cracker_id"]})
        print "Cracking started!"
        try:
            return new["user_processes"][0]["id"]
        except:
            print new

    def log_trolling(self,number,text=None):
        targets = []
        if text == None:
            text = "\n".join(raw_input("Enter log text...\n").split("\\n"))
        text = "&lt;br/&gt;".join(text.split("\n"))
        for x in range(int(number/5)):
            users = self.get_req("https://api.hackex.net/v5/users_random",params={"count":"5"})["users"]
            for user in users:
                targets.append(user)

        for x in range(0,len(targets)):
            self.replace_log(targets[x]["id"],text=text)
            print "Done",x+1,"of",len(targets)
            time.sleep(1)

    def ur_nan(self,number):
        targets = []
        for x in range(int(number/5)):
            users = self.get_req("https://api.hackex.net/v5/users_random",params={"count":"5"})["users"]
            for user in users:
                targets.append(user)
                
        for x in range(0,len(targets)):
            text = "Dear "+targets[x]["username"]+",\n\nur a chicken.\n\nfrom ur nan"
            text = "&lt;br/&gt;".join(text.split("\n"))
            self.replace_log(targets[x]["id"],text)
            print "Done",x+1,"of",len(targets)
            time.sleep(1)

    def git_chickened(self,victim_id):
        username = self.get_req("https://api.hackex.net/v5/user_victim",params={"victim_user_id":str(victim_id)})["user"]["username"]
        self.replace_log(victim_id,text="Dear "+username+",\n\nur a chicken.\n\nfrom ur nan")
        
    def log_trolling_a(self,number,text=None):
        targets = []
        if text == None:
            text = "\n".join(raw_input("Enter log text...\n").split("\\n"))
        text = "&lt;br/&gt;".join(text.split("\n"))
        for x in range(int(number/5)):
            users = self.get_req("https://api.hackex.net/v5/users_random",params={"count":"5"})["users"]
            for user in users:
                targets.append(user)

        for x in range(0,len(targets)):
            self.append_log(targets[x]["id"],text)
            print "Done",x+1,"of",len(targets)
            time.sleep(1)

    def shit_stirring(self,number,verbose=False):
        targets = []
        victims = []
        if targets == []:
            for x in range(int(number/5)):
                users = self.get_req("https://api.hackex.net/v5/users_random",params={"count":"5"})["users"]
                for user in users:
                    targets.append(user)
        if victims == []:
            for x in range(int(number/5)):
                users = self.get_req("https://api.hackex.net/v5/users_random",params={"count":"5"})["users"]
                for user in users:
                    victims.append(user)
        if len(victims) != len(targets):
            return "Lists not equal!"

        for x in range(0,len(targets)):
            curtime = time.localtime()
            mon = str(curtime[1])
            if len(mon) == 1:
                mon = "0"+mon
            day = str(curtime[2])
            if len(day) == 1:
                day = "0"+day
            hour = str(curtime[3])
            if len(hour) == 1:
                hour = "0"+hour
            mini = str(curtime[4])
            if len(mini) == 1:
                mini = "0"+mini
            curtime = "["+mon+"-"+day+" "+hour+":"+mini+"]"
            text = curtime+" "+victims[x]["ip"]+" logged in.&lt;br/&gt;"
            if verbose:
                print "Adding \""+text+"\" to",targets[x]["username"]+"("+targets[x]["id"]+")"
            try:
                obj.append_log(targets[x]["id"],text)
            except UnicodeEncodeError:
                print "UNICODE ERROR"
            print "Done",x+1,"of",len(targets)
            time.sleep(1)

    def buy(self,stuff=None,update=True):
        if stuff == None:
            stuff = raw_input("1) Firewall\n2) Bypasser\n3) Cracker\n4) Encryptor\n5) Antivirus\n6) Spam\n7) Spyware\n\nSelect software to buy... ")
        purchase = self.post_req("https://api.hackex.net/v5/store_purchase",params={"software_type_id":stuff})
        if purchase["success"]:
            print "Purchase made!"
        else:
            print "Purchase failed!"
        if update:
            data = self.get_req("http://api.hackex.net/v5/user_victim",{"victim_user_id":self.other_data["id"]})
            software = data["user_software"]
            softwares = {}
            for x in software:
                softwares[x["name"]] = x
            software_types = ["Firewall","Bypasser","Antivirus","Spyware","Firewall","Password Encryptor","Password Cracker","Spam","Notepad"]
            for x in software_types:
                try:
                    x = softwares[x]
                except:
                    softwares[x] = {"software_id":"0"}
            self.other_data["spam_id"] = softwares["Spam"]["software_id"]
            self.other_data["bypasser_id"] = softwares["Bypasser"]["software_id"]
            self.other_data["cracker_id"] = softwares["Password Cracker"]["software_id"]
        return purchase

    def take_monies(self,victim_id):
        data = self.get_req("http://api.hackex.net/v5/user_victim",params={"victim_user_id":str(victim_id)})
        money = data["user_bank"]["checking"]
        while int(money) > 0:
            if int(money) > 10000000:
                money = "10000000"
            process = self.post_req("https://api.hackex.net/v5/bank_transfer_from_victim",params={"victim_user_id":str(victim_id),"amount":int(money)})
            if process["success"]:
                print "Money taken!"
            else:
                if process["message"] == 'Max Daily Transfers Exceeded.':
                    print "Hit the transfer limit!"
                else:
                    print "Failed to take money!"
                return process
            data = self.get_req("http://api.hackex.net/v5/user_victim",params={"victim_user_id":str(victim_id)})
            money = data["user_bank"]["checking"]
        print "No money to take!"

    def take_amount(self,victim_id,amount):
        if int(amount) > 10000000:
            print "Taking too much!"
            return 0
        data = self.get_req("http://api.hackex.net/v5/user_victim",params={"victim_user_id":str(victim_id)})
        money = data["user_bank"]["checking"]
        if int(money) < int(amount):
            print "Not enough money in checking!"
            return 0
        process = self.post_req("https://api.hackex.net/v5/bank_transfer_from_victim",params={"victim_user_id":str(victim_id),"amount":int(amount)})
        if process["success"]:
            print "Money taken!"
        else:
            if process["message"] == 'Max Daily Transfers Exceeded.':
                print "Hit the transfer limit!"
            else:
                print "Failed to take money!"
            return process

    def have_cracked(self,victim_id):
        data = self.get_req("http://api.hackex.net/v5/user_victim",params={"victim_user_id":str(victim_id)})
        software = data["user_software"]
        softwares = {}
        for x in software:
            softwares[x["name"]] = x
        software_types = ["Firewall","Bypasser","Antivirus","Spyware","Firewall","Password Encryptor","Password Cracker","Spam","Notepad"]
        for x in software_types:
            try:
                x = softwares[x]
            except:
                softwares[x] = {"software_level":"0"}

        cracked = self.get_req("https://api.hackex.net/v5/is_password_cracked",params={"victim_user_id":str(victim_id),"encryption_level":softwares["Password Encryptor"]["software_level"]})
        return cracked
        

    def new_account(self,username,email,password):
        params = {"email":email,"os_type_id":"1","password":password,"username":username}
        login = self.post_req("https://api.hackex.net/v5/user",params=params)
        while not login["success"]:
            login = self.post_req("https://api.hackex.net/v5/user",params=params)
        #print login
        self.other_data["username"] = login["user"]["username"]
        self.other_data["level"] = login["user"]["level"]
        self.other_data["ip"] = login["user"]["ip"]
        self.other_data["id"] = login["user"]["id"]
        self.headers["X-API-KEY"] = login["user"]["auth_token"]

        data = self.get_req("http://api.hackex.net/v5/user_victim",{"victim_user_id":self.other_data["id"]})
        software = data["user_software"]
        softwares = {}
        for x in software:
            softwares[x["name"]] = x
        software_types = ["Firewall","Bypasser","Antivirus","Spyware","Firewall","Password Encryptor","Password Cracker","Spam","Notepad"]
        for x in software_types:
            try:
                x = softwares[x]
            except:
                softwares[x] = {"software_id":"0"}
        self.other_data["spam_id"] = softwares["Spam"]["software_id"]
        self.other_data["bypasser_id"] = softwares["Bypasser"]["software_id"]
        self.other_data["cracker_id"] = softwares["Password Cracker"]["software_id"]

    def generate_targets(self,number,file_object):
        targets = []
        while len(targets) < number:
            users = self.get_req("https://api.hackex.net/v5/users_random",params={"count":"5"})
            while not users["success"]:
                users = self.get_req("https://api.hackex.net/v5/users_random",params={"count":"5"})
            users = users["users"]
            for user in users:
                if user["id"] not in targets:
                    targets.append(user["id"])
                    print "Done",targets.index(user["id"])+1,"of",number
        targets = "\n".join(targets)
        file_object.write(targets)
        file_object.close()
