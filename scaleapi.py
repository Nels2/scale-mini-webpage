from config import *
import pickle

# begin SCALE API stuff
host = ""
url = 'https://{0}/rest/v1'.format(host)


api_headers = pickle.load( open( "/Projects/scale_metrics/session/devcall_sessionLogin.p", "rb"))
cookie_value = api_headers.get("Cookie", "")
print(f"Session Loaded! Session will be used for the majority of tasks, except for a few.. {cookie_value}")

credentials = f"Basic {xcred}"  
rest_opts = {
    "Content-Type": "application/json",
    "Authorization": credentials,
    "Cookie": cookie_value,
    "Connection": "keep-alive"
}


class InternalException(Exception): #needed for scale-api requests involving vdi/snap/clone creation
    pass

class TaskException(InternalException): #needed for scale-api requests involving vdi/snap/clone creation
    def __init__(self, tag, message, parameters):
        self.tag = tag
        self.message = message
        self.parameters = parameters

    def __str__(self):
        return '%s "%s" %s' % (self.tag, self.message, self.parameters)

class HTTPResponseException(InternalException): #needed for scale-api requests involving vdi/snap/clone creation
    def __init__(self, response):
        self.response = response
        self.body = response.read()

    def __repr__(self):
        return str(self)

    def __str__(self):
        return str(self.response.status) + ": " + str(self.body)

def get_credentials(): #needed for scale-api requests involving vdi/snap/clone creation
    username = "devcall"
    password = "8pL$eJ#4dK2B6@N1M9D4g"
    return str(base64.b64encode(bytes('{0}:{1}'.format(username, password), 'utf-8')), 'utf-8')

def get_connection(host): #needed for scale-api requests involving vdi/snap/clone creation
    timeout = 120
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.verify_mode = ssl.CERT_NONE

    return http.HTTPSConnection(host, timeout=timeout, context=context)

def get_response(connection): #needed for scale-api requests involving vdi/snap/clone creation
    response = connection.getresponse()
    if response.status != http.OK:
        raise HTTPResponseException(response)

    return json.loads(response.read().decode("utf-8"))

def wait_for_task_completion(connection, task_id): #needed for scale-api requests involving vdi/snap/clone creation
    inprogress = True
    while inprogress:
        connection.request(
            'GET', '{0}/{1}'.format(url, 'TaskTag/{0}'.format(task_id)), None, rest_opts)
        task_status = get_response(connection)[0]
        if task_status['state'] == 'ERROR':
            raise TaskException(
                task_id, task_status['formattedMessage'], task_status['messageParameters'])
        if task_status['state'] == 'COMPLETE':
            inprogress = False


@app.route('/scale_api_page', methods=['GET', 'POST']) # This goes to the actual dash page
def scale_api_page():
    api_result = "No Command Yet."
    return render_template('pubdocs/net/scale_api.html', result=api_result)

@app.route('/scale_api/<cmd>', methods=['GET', 'POST']) # This accepts commands from page, for auth / de-auth & ping
def scale_api(cmd):
    # Ping Server Cluster Host
    #print("CMD Sent from Website: "+ str(cmd)) #debugprints
    if cmd == "login":
        #/usr/bin/bash /Projects/scale_metrics/
        #api_result = os.popen("curl -k -X 'POST' 'https://172.18.33.217/rest/v1/login' -H 'accept: application/json' -H 'Content-Type: application/json' -d '{\"username\": \"devcall\", \"password\": \"8pL$eJ#4dK2B6@N1M9D4g\", \"useOIDC\": false}'").read()
        api_result = os.popen("/usr/bin/bash /Projects/scale_metrics/run_GenDevSession.sh").read()
    elif cmd == "logout":
        # logout of API
        #api_result = os.popen("curl -k -X 'POST' 'https://172.18.33.217/rest/v1/logout' -H 'accept: */*' -H 'Content-Type: application/json' -d '{\"username\": \"devcall\", \"password\": \"8pL$eJ#4dK2B6@N1M9D4g\", \"useOIDC\": false}'").read()
        api_result = os.popen("/usr/bin/bash /Projects/scale_metrics/run_KillDevSession.sh").read()
    else:
        api_result = "No command yet."

    return render_template('pubdocs/net/scale_api.html', result=api_result)

# From here the SCALE_API gets more complex.

@app.route('/scale_api_user_create', methods=['POST']) # This is built for user creation cmds involivng the api.
def scale_api_user_create():
    if request.method == 'POST': #this is for user creation 
        pre_username = request.form.get('uname')
        pre_password = request.form.get('pswd')
        pre_fullName = request.form.get('fullName')
        pre_roleUUIDs = request.form.get('roleuuids')
        pre_sessionLimit = request.form.get('sessionLimit')
        print(f"converting following INFO.... username: {pre_username}, pswd: {pre_password}, fn: {pre_fullName}, ru: {pre_roleUUIDs}, sL: {pre_sessionLimit}")
        username = (f'"{pre_username}"')
        password = (f'"{pre_password}"')
        fullName = (f'"{pre_fullName}"')
        roleUUIDs = (f'"{pre_roleUUIDs}"')
        sessionLimit = int(pre_sessionLimit)
        print(f"Conversion success! .... username: {username}, pswd: {password}, fn: {fullName}, ru: {roleUUIDs}, sL: {sessionLimit}")

        endpoint = "User"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "POST"
        payload = f"{{\"username\": \"{username}\", \"password\": \"{password}\", \"fullName\": \"{fullName}\", \"roleUUIDs\": \"[{roleUUIDs}]\", \"sessionLimit\": {sessionLimit}}}"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" -d "{payload}" | jq'
        print(f"Attempting to talk to {url2use}..")
        api_result = os.popen(command).read()

    flash(f'{username}  has been created successfully!', 'success')
    
    return render_template('pubdocs/net/scale_api.html', result=api_result)

@app.route('/scale_api_cluster/<cmd>', methods=['GET', 'POST']) # This is built for cluster cmds involivng the api.
def scale_api_cluster(cmd):
    # Ping Server Cluster Host
    #print("CMD Sent from Website: "+ str(cmd)) #debugprints
    if cmd == "ping":
        # Get result from API
        api_request = f"curl -s -k --cookie '{cookie_value}'  -X GET https://172.18.33.217/rest/v1/ping  -H 'accept: application/json'"
        api_result = os.popen(api_request).read()
        #api_result = os.popen(f"curl -k -X 'GET' 'https://172.18.33.217/rest/v1/ping'  -H '{api_headers}'").read()


        if api_result == '{"status":"Active"}':
            api_result = "SCALE Cluster is currently active, and communicating correctly with nmap-x!"
        else:
            api_result = "SCALE Cluster Communications appear to be offline."
    elif cmd == "status":
        api_result = f"COMMAND '{cmd}' IS NOT YET IMPLEMENTED!"
    elif cmd == "users":
        endpoint = "User"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()


    elif cmd == "updates_get":
        api_result = os.popen(f"curl -k -X 'GET' 'https://172.18.33.217/rest/v1/Update'   -H 'accept: application/json'   -H 'Authorization: Basic {xcred}' | jq").read()
        if api_result == '[]':
            api_result = "No Updates are Currently Available. Please Try Again Later."
        else:
            api_result = api_result
    elif cmd == "updates_apply":
        api_result = f"COMMAND '{cmd}' IS NOT YET IMPLEMENTED!"
    elif cmd == "nodes":
        endpoint = "Node"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

    elif cmd == "ping_remote":
        endpoint = "RemoteClusterConnection"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

    elif cmd == "isos":
        endpoint = "ISO"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

    elif cmd == "conditions":
        endpoint = "Condition"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

    elif cmd == "conditions_filter-set":
        endpoint = "Condition/filter?includeSet=true"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()
        
    elif cmd == "conditions_filter-notok":
        endpoint = "Condition/filter?includeNotOK=true"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()
        
    elif cmd == "config_drives":
        endpoint = "Drive"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json"'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()
        
    elif cmd == "virt_drives":
        endpoint = "VirtualDisk"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()
        
    elif cmd == "config_dns":
        endpoint = "DNSConfig"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()
        
    elif cmd == "registration":
        endpoint = "ClusterRegistrationData"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()
        
    elif cmd == "roles":
        endpoint = "Role"
        url2use = f"https://{host}/rest/v1/{endpoint}"
    
        command = f'curl -s --cookie "{cookie_value}" -X GET {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

    elif cmd == "timesources":
        endpoint = "TimeSource"
        url2use = f"https://{host}/rest/v1/{endpoint}"
    
        command = f'curl -s --cookie "{cookie_value}" -X GET {url2use}  -H "accept: application/json"'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()
    else:
        api_result = "No command yet."


    flash(f'Sent {cmd}.', 'success')
    return render_template('pubdocs/net/scale_api.html', result=api_result)

@app.route('/scale_api_alerts/<cmd>', methods=['GET', 'POST']) # This is built for alert(s) cmds involivng the api.
def scale_api_alerts(cmd):
    # here is alerts piece defined
    if cmd == "create_alert":
        api_result = f"COMMAND '{cmd}' IS NOT YET IMPLEMENTED!"
    elif cmd == "edit_alert":
        api_result = f"COMMAND '{cmd}' IS NOT YET IMPLEMENTED!"
    elif cmd == "view_alert_targets":
        endpoint = "AlertEmailTarget"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

    elif cmd == "view_alert_smtp_config":
        endpoint = "AlertSMTPConfig"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

    elif cmd == "view_alert_syslog_target":
        endpoint = "AlertSyslogTarget"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

        if api_result == '[]':
            api_result = "A Response was Received, but no data was returned. Please Try Again Later."
        else:
            api_result = api_result
    elif cmd == "delete_alert":
        api_result = f"COMMAND '{cmd}' IS NOT YET IMPLEMENTED!"
    else:
        api_result = "No command yet."

    return render_template('pubdocs/net/scale_api.html', result=api_result)

@app.route('/scale_api_alerts_create_target', methods=['POST']) # This is built for creating an alert target.
def scale_api_alerts_create_target():
    if request.method == 'POST': #this is for VDI creation 
        pre_alertTagUUID = request.form.get('alert_TagUUID')
        pre_emailAddress = request.form.get('alert_email')
        pre_resendDelay = request.form.get('alert_sendDelay')
        pre_silentPeriod = request.form.get('alert_sp')
        
        print(f"converting following INFO.... Alert Tag UUID: {pre_alertTagUUID}, email: {pre_emailAddress}, rDelay: {pre_resendDelay}, sP: {pre_silentPeriod}")
        alertTagUUID = (f'"{pre_alertTagUUID}"')
        emailAddress = (f'"{pre_emailAddress}"')
        resendDelay = int(pre_resendDelay)
        silentPeriod = int(pre_silentPeriod) 
        print(f"Conversion success! .... Alert Tag UUID: {alertTagUUID}, email: {emailAddress}, rDelay: {resendDelay}, sP: {silentPeriod}")
        
        endpoint = "AlertEmailTarget"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "POST"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" -d "{{\"alertTagUUID\": \"{alertTagUUID}\", \"emailAddress\": \"{emailAddress}\", \"resendDelay\": {resendDelay}, \"silentPeriod\": {silentPeriod}}}" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()
        
    flash(f' Alert Target "{alertTagUUID}" has been created successfully!', 'success')
    
    return render_template('pubdocs/net/scale_api.html', result=api_result)


@app.route('/scale_api_alerts_create', methods=['POST']) # This is built for testing a alert target.
def scale_api_alerts_create():
    if request.method == 'POST': #this is for VDI creation 
        pre_alertTagUUID = request.form.get('alert_TagUUID')
        
        print(f"converting following INFO.... Alert Tag UUID: {pre_alertTagUUID}")
        alertTagUUID = (f'"{pre_alertTagUUID}"')
        print(f"Conversion success! .... Alert Tag UUID: {alertTagUUID}")
        
        endpoint = f"AlertEmailTarget/{alertTagUUID}/test"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "POST"
        payload = f"{{\"alertTagUUID\": \"{alertTagUUID}\", \"emailAddress\": \"{emailAddress}\", \"resendDelay\": {resendDelay}, \"silentPeriod\": {silentPeriod}}}"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" -d "{payload}" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()
        

    flash(f' Alert Target "{alertTagUUID}" has been sent a test email successfully!', 'success')
    
    return render_template('pubdocs/net/scale_api.html', result=api_result)

@app.route('/scale_api_alerts_smtp_create', methods=['POST']) # This is built for SMTP Alert Target.
def scale_api_alerts_smtp_create():
    if request.method == 'POST': #this is for VDI creation 
        pre_smtpServer = request.form.get('alert_smtpServer')
        pre_port = request.form.get('alert_port')
        useSSL = request.form.get('alert_SSL')
        useAuth = request.form.get('alert_auth')
        pre_authUser = request.form.get('alert_aUser')
        pre_authPassword = request.form.get('alert_aPass')
        pre_fromAddress = request.form.get('alert_fromEmail')

        print(f"converting following INFO.... smtp server: {pre_smtpServer}, port: {pre_port}, uSSL: {useSSL}, uAuth: {useAuth}, user: {pre_authUser}, uPass: {pre_authPassword}, from Email: {pre_fromAddress}")
        smtpServer = (f'"{pre_smtpServer}"')
        port = int(pre_port)
        authUser = (f'"{pre_authUser}"')
        authPassword = (f'"{pre_authPassword}"')
        fromAddress = (f'"{pre_fromAddress}"')
        print(f"Conversion success! .... smtp server: {smtpServer}, port: {port}, uSSL: {useSSL}, uAuth: {useAuth}, user: {authUser}, uPass: {authPassword}, from Email: {fromAddress}")
        
        endpoint = "AlertSMTPConfig"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "POST"
        payload = f"{{\"smtpServer\": \"{smtpServer}\", \"port\": \"{port}\", \"useSSL\": {useSSL}, \"useAuth\": {useAuth}, \"fromAddress\": {fromAddress}}}"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" -d "{payload}" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()
    flash(f'SMTP Server {pre_smtpServer} has been added successfully!', 'success')

    return render_template('pubdocs/net/scale_api.html', result=api_result)



@app.route('/scale_api_snapshots/<cmd>', methods=['GET', 'POST']) # This is built for snapshot(s) cmds involivng the api.
def scale_api_snapshots(cmd):
    if cmd == "pull_snaps":
        api_result = os.popen(f"/usr/bin/bash /Projects/scale_metrics/run_getSnapshotReportAll.sh").read()
    elif cmd == "check_csnaps":
        endpoint = "VirDomainSnapshot"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        #print(f"using: {command}")
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

    elif cmd == "check_snaps":
        api_result = os.popen(f"/usr/bin/bash /Projects/scale_metrics/run_getSnapshotReportRemote.sh").read()
    elif cmd == "check_snapSchedule":
        endpoint = "VirDomainSnapshotSchedule"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

    elif cmd == "delete_snap":
        api_result = f"COMMAND '{cmd}' IS NOT YET IMPLEMENTED!"
    else:
        api_result = "No command yet, or the one you tried has not yet been implemented."
    flash(f'Sent {cmd} successfully.', 'success')
    return render_template('pubdocs/net/scale_api.html', result=api_result)

@app.route('/scale_api_snapshots_create', methods=['POST']) # This is built for ONLY snapshot creation cmds involivng the api.
def scale_api_snapshots_create():
    if request.method == 'POST': #this is for snapshot creation 
        pre_domainUUID = request.form.get('snap_UUID')
        pre_label = request.form.get('snap_label')
        pre_type = request.form.get('snap_type')
        pre_automatedTriggerTimestamp = request.form.get('automatedTriggerTimestamp')
        pre_localRetainUntilTimestamp = request.form.get('localRetainUntilTimestamp')
        pre_remoteRetainUntilTimestamp = request.form.get('remoteRetainUntilTimestamp')
        pre_blockCountDiffFromSerialNumber = request.form.get('blockCountDiffFromSerialNumber')
        pre_replication = request.form.get('replication')
        print(f"converting: {pre_domainUUID},{pre_label}, {pre_type}, {pre_automatedTriggerTimestamp}, {pre_localRetainUntilTimestamp}, {pre_remoteRetainUntilTimestamp}, {pre_blockCountDiffFromSerialNumber}, {pre_replication}")
        domainUUID = (f'"{pre_domainUUID}"')
        label = (f'"{pre_label}"')
        snap_type = (f'"{pre_type}"')
        automatedTriggerTimestamp = int(pre_automatedTriggerTimestamp)
        localRetainUntilTimestamp = int(pre_localRetainUntilTimestamp)
        remoteRetainUntilTimestamp = int(pre_remoteRetainUntilTimestamp)
        blockCountDiffFromSerialNumber = int(pre_blockCountDiffFromSerialNumber)
        replication = (f'"{pre_replication}"')
        print(f"Conversion success! .. {domainUUID},{label}, {snap_type}, {automatedTriggerTimestamp}, {localRetainUntilTimestamp}, {remoteRetainUntilTimestamp}, {blockCountDiffFromSerialNumber}, {replication}")
        
        endpoint = "VirDomainSnapshot"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "POST"
        payload = f"{{\"domainUUID\": \"{domainUUID}\", \"label\": \"{label}\", \"snap_type\": {snap_type}, \"automatedTriggerTimestamp\": {automatedTriggerTimestamp}, \"remoteRetainUntilTimestamp\": {remoteRetainUntilTimestamp}, \"blockCountDiffFromSerialNumber\": {blockCountDiffFromSerialNumber}, \"replication\": {replicatione}}}"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" -d "{payload}" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()
        
    flash(f'Action SNAP_CREATE performed', 'success')
    return render_template('pubdocs/net/scale_api.html', result=api_result)

@app.route('/scale_api_vdi/<cmd>', methods=['GET', 'POST']) # This is built for VDI info cmds involivng the api.
def scale_api_vdi(cmd):
    # Ping Server Cluster Host
    #print("CMD Sent from Website: "+ str(cmd)) #debugprints
    if cmd == "VDI_pull":
        endpoint = "VirDomain"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()
    elif cmd == "VDI_affinity":
        api_result = os.popen(f"pwsh -File /Projects/scale_metrics/get_AffinityReport.ps1 172.18.33.217 devcall {scaleGUIpwd}").read()
    elif cmd == "VDI_net":
        endpoint = "VirDomainNetDevice"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

    elif cmd == "VDI_stor":
        endpoint = "VirDomainBlockDevice"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

    elif cmd == "VDI_reps":
        endpoint = "VirDomainReplication"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()
    else:
        api_result = "No command yet."
    return render_template('pubdocs/net/scale_api.html', result=api_result)

@app.route('/scale_api_vdi_create', methods=['POST']) # This is built for creating a VDI involivng the api.         --- uses connection.request
def scale_api_vdi_create():
    if request.method == 'POST': #this is for VDI creation 
        
        VDIname = request.form.get('VDI_name')
        VDIdesc = request.form.get('VDI_description')
        vtags = request.form.get('VDI_dept')
        operatingSystem = request.form.get('VDI_os')
        pre_vdi_cpu = request.form.get('VDI_cpu')
        vdi_cpuType = request.form.get('VDI_cpuType')
        machineType = request.form.get('VDI_machineType')
        pre_vdi_memory = request.form.get('VDI_memory')
        pre_vdi_blockDev = request.form.get('VDI_blockDev')
        blockDevType = request.form.get('VDI_blockDevType')
        blockDevCache = request.form.get('VDI_blockDevCache')
        netDev = request.form.get('VDI_netDev')
        pre_vdi_netDevVLAN = request.form.get('VDI_netDevVLAN')
        pre_vdi_iso = request.form.get('VDI_iso')

        items = [
            VDIname, 
            VDIdesc, 
            vtags, 
            operatingSystem, 
            pre_vdi_cpu, 
            vdi_cpuType, 
            machineType, 
            pre_vdi_memory, 
            pre_vdi_blockDev, 
            blockDevType,
            blockDevCache, 
            netDev,
            pre_vdi_netDevVLAN,
            pre_vdi_iso
        ]
        #print("*#*#*#* DBEUG *#*#*#*")
        #for item in items:
        #    print(f"REQUESTed: {item}")
        #print("*#*#*#* DEBUG *#*#*#*")

        numVCPU = int(pre_vdi_cpu)
        vlan = int(pre_vdi_netDevVLAN)
        mem = int(pre_vdi_memory)
        block_dev_capacity = int(pre_vdi_blockDev)
        
        default_vm = {
            'dom': {
                'name': VDIname,
                'description': 'Assigned to: '+str(VDIdesc),
                'operatingSystem': operatingSystem,
                'mem': mem,  # 8GiB
                'numVCPU': numVCPU,
                'blockDevs': [{
                    'capacity': block_dev_capacity,
                    'type': blockDevType,
                    'cacheMode': blockDevCache
                }],
                'netDevs': [{
                    'type': netDev,
                    'vlan': vlan #VLAN 1 for physical work stations , 2 for VDI
                }],
                'machineType': machineType,
                'cpuType': vdi_cpuType,
                'tags': ",".join(['SACU_VDI', vtags])
            },
            'options': {
                #   attachGuestToolsISO == false
                #  attachclientbootISO = true
            }
            
        }
        print(">> Creating '"+str(VDIname)+"' VM..")
        connection = get_connection(host)
        connection.request(
            'POST', '{0}/VirDomain'.format(url), json.dumps(default_vm), rest_opts)
        result = get_response(connection)
        wait_for_task_completion(connection, result['taskTag'])
        vmUUID = result['createdUUID']
        vdi_isox = f"scribe/{pre_vdi_iso}"
        vdi_iso = str(vdi_isox)
        print(f">> '{VDIname}' has been created. continuing..")
        print(f"| Attaching {vdi_iso} iso for '{VDIname}'..")

        if pre_vdi_iso == "2c1c0864-12f7-44bc-bcc1-13ef4415dbed": 
            capi = 56623104
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")
            #clientboot s53 SB.iso

        elif pre_vdi_iso == "4598846f-bc77-4889-97e5-794d93a79824":
            capi = 52428800
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")
            #clientboot s53 noSB.iso

        elif pre_vdi_iso == "701dcff5-3390-450d-b36a-7f827dfefc16":
            capi = 52428800
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")
            #clientboot s99 noSB.iso

        elif pre_vdi_iso == "701dcff5-3390-450d-b36a-7f827dfefc16":
            capi = 52428800
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")
            #clientboot s99 noSB.iso

        #END CLIENTBOOT SECTION - BEGIN LINUX ISOs

        elif pre_vdi_iso == "8d6069e9-8e00-4771-8471-1dcdcb6bcbaf":
            capi = 553648128
            #GParted ISO
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")

        elif pre_vdi_iso == "58a832f5-b77b-49f0-8917-80af3aa87b08":
            capi = 662700032
            #debian ISO
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")
        elif pre_vdi_iso == "544405f3-9875-4668-b3cd-a798267597af":
            capi = 1248854016
            #arch ISO
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")
        elif pre_vdi_iso == "2618fa87-ec57-412a-97f1-4a90034d9090":
            capi = 4327473152
            #manjaro ISO
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")
        elif pre_vdi_iso == "bc520b68-0ae3-4e16-b67b-314fdf08fb61":
            capi = 1086324736
            #rocky ISO
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")
        elif pre_vdi_iso == "bb5a36b4-6fc3-44c9-bc25-f2600a13f66a":
            capi = 6203375616
            #Ubuntu ISO
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")

        # END LINUX ISOs - BEGIN WINDOWS ISOs

        elif pre_vdi_iso == "f589c5e2-5ae7-4d39-8f5e-b3c9c86f89a6":
            capi = 5044699136
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")
            #Windows Server 2022 ISO

        elif pre_vdi_iso == "7fc08795-f920-442a-b9d2-3a96486b0686":
            capi = 6014631936
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")
            #Windows Server 2025 ISO

        #begin winodws client editions
        elif pre_vdi_iso == "fd9d5e1e-fe62-49a5-818a-23983b552309":
            capi = 6115295232
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")
            #Windows 10 22H2 ISO
        elif pre_vdi_iso == "523da47c-511c-4900-b160-950e4e0e1597":
            capi = 5842665472
            print(f"| --> Updated Capacity to {capi} for {pre_vdi_iso}")
            #Windows 11 24H2 ISO


        else:
            capi = 57671680
        block_device_attrs = {
            'virDomainUUID': vmUUID,
            'capacity': capi,
            'path': vdi_iso,  #clientboot_latest.iso
            #'path': "scribe/a4326a7d-dd08-414f-abd4-47483032a9c0",  #clientboot.iso #switched on july 23rd, 2024
            #'path': "scribe/7ac0e95f-1718-4cde-8753-a154e5d2d043", #pxe1.iso
            'slot': -1,
            'type': 'IDE_CDROM',
            'cacheMode': 'WRITETHROUGH'
        }
        connection.request('POST', '{0}/VirDomainBlockDevice'.format(url), json.dumps(
            block_device_attrs), rest_opts)
        result = get_response(connection)
        wait_for_task_completion(connection, result['taskTag'])
        print("| clientboot iso has been added to '"+str(VDIname)+"' VM without errors.")
        print(">> Starting '"+ str(VDIname) + "' VM..")
        start_vm = [{
            'actionType': 'START',
            'virDomainUUID': vmUUID
        }]
        connection.request(
            'POST', '{0}/VirDomain/action'.format(url), json.dumps(start_vm), rest_opts)
        result = get_response(connection)
        wait_for_task_completion(connection, result['taskTag'])
        print(">> "+ str(VDIname) + "' VM has been started! ..")
        print("   ")
        print("   ")
        print("VDI Name:  "+str(VDIname))
        print("vm UUID:   "+str(vmUUID))
        print("vmUUID is used for various API requests.")
        api_result = f"{VDIname} [UUID: {vmUUID}] has been created succesfully!"
        #return redirect(url_for('pdfm'))
        flash(f'{VDIname}  has been created successfully!', 'success')
        return render_template('pubdocs/net/scale_api.html', result=api_result)

@app.route('/scale_api_vdi_clone', methods=['POST']) # This is built for cloning a VDI involivng the api.           --- uses connection.request
def scale_api_vdi_clone():
    if request.method == 'POST': #this is for VDI creation 
        
        VDIname = request.form.get('VDI_name')
        VDIdesc = request.form.get('VDI_description')
        vtags = request.form.get('VDI_dept')
        vmUUID = request.form.get('vmUUID')
        
        vm_clone_attrs = {
            'template': {
                'name': VDIname,
                'description': 'Assigned to: '+str(VDIdesc),
                'operatingSystem': 'os_windows_server_2012',
                'netDevs': [{
                    'type': 'VIRTIO',
                    'vlan': 1 #VLAN 1 for physical work stations , 2 for VDI
                }],
                'machineType': 'scale-uefi-tpm-9.3',
                "machineTypeKeyword": "tpm",
                "cpuType": "intel-core-cascadelake-amd64-9.4",
                'tags': ",".join(['SACU_VDI', vtags])
            }
        }
        connection = get_connection(host)
        connection.request('POST', '{0}/VirDomain/{1}/clone'.format(
            url, vmUUID), json.dumps(vm_clone_attrs), rest_opts)
        result = get_response(connection)
        wait_for_task_completion(connection, result['taskTag'])
        cloneUUID = result['createdUUID']
        
        print(">>> Successfully Cloned "+ str(vmUUID) +" to "+str(VDIname))
        print(">> Starting "+str(VDIname)+"...")
        start_vm = [{
            'actionType': 'START',
            'virDomainUUID': cloneUUID
        }]
        connection.request(
            'POST', '{0}/VirDomain/action'.format(url), json.dumps(start_vm), rest_opts)
        result = get_response(connection)
        wait_for_task_completion(connection, result['taskTag'])
        print(">>> "+str(VDIname)+" has been started! ...")
        
        print("   ")
        print("   ")
        api_result = f"{vmUUID} has been cloned as {VDIname} [UUID: {cloneUUID}] successfully!"
        flash(f'Clone Creation for {VDIname} successfully!', 'success')
        return render_template('pubdocs/net/scale_api.html', result=api_result)

@app.route('/scale_api_vdi_change', methods=['POST']) # This is built for changing state of a VDI involivng the api.          --- uses connection.request   
def scale_api_vdi_change():
    if request.method == 'POST': 
        
        vmUUID = request.form.get('VDI_uuid')
        actionState = request.form.get('VDI_desiredState')
        cause_why = request.form.get('VDI_desiredSate_why')
        nodeuuid = request.form.get('VDI_desiredSate_nodemigrateUUID')

        if nodeuuid == "DEFAULT":
            print("running default route...")
            start_vm = [{
                'actionType': actionState,
                'virDomainUUID': vmUUID,
                'cause': cause_why
            }]
        else: #Typically this route should only hpppen if live migrate is chosen, requiring a node to be chosen.
            
            if nodeuuid == "NODE1":
                nodeuuid = "13e7aebc-439f-42bb-99d7-7a3919cb634c"
            elif nodeuuid == "NODE2":
                nodeuuid = "b66cfd90-a9d8-421c-bd54-88e151840413"
            elif nodeuuid == "NODE3":
                nodeuuid = "b66cfd90-a9d8-421c-bd54-88e151840413"
            print(f">>> running {actionState} route for {vmUUID} to {nodeuuid} ...")

            start_vm = [{
                'actionType': actionState,
                'virDomainUUID': vmUUID,
                'cause': cause_why,
                'nodeUUID': nodeuuid
            }]
        #print(f"[{vmUUID}], [{actionState}], [{cause_why}], [{nodeuuid}]")
        
        connection = get_connection(host)
        connection.request(
            'POST', '{0}/VirDomain/action'.format(url), json.dumps(start_vm), rest_opts)
        result = get_response(connection)
        wait_for_task_completion(connection, result['taskTag'])
        print(f">>> {actionState} has been performed on {vmUUID}! ...")
        
        print("   ")
        print("   ")
        api_result = f">>> {actionState} has been performed on {vmUUID}! ..."
        flash(f'Action Performed.', 'success')
        return render_template('pubdocs/net/scale_api.html', result=api_result)

@app.route('/scale_api_vdi_switch', methods=['POST', 'PATCH']) # This is built for editing prooperties of a VDI involivng the api. --- uses connection.request
def scale_api_vdi_switch():
    if request.method == 'POST': #this is for VDI Editing, specifically the CPU and MachineType Switch.
        
        vmUUID = request.form.get('VDI_uuid')
        cpuType = request.form.get('VDI_desired_cpuType')
        machineType = request.form.get('VDI_desired_machineType')

        payload = json.dumps({
            "machineType": machineType,
            "cpuType": cpuType
        })
        
        connection = get_connection(host)
        patch_url = f"https://{host}/rest/v1/VirDomain/{vmUUID}"
        connection.request(
            'PATCH', patch_url, payload, rest_opts)
        result = get_response(connection)
        wait_for_task_completion(connection, result['taskTag'])
        print(f">>> VDI Property Edit has been performed on {vmUUID}! ...")
        
        print("   ")
        print("   ")
        api_result = f">>> Property Edit has been performed on {vmUUID}! ..."
        flash(f'Action Performed.', 'success')
        return render_template('pubdocs/net/scale_api.html', result=api_result)


@app.route('/scale_api_vdi_search/') # This does a seach for (a) vdi on the page
def scale_api_vdi_search():
    domainUUID = request.args.get('vmUUID')
    search_choice = request.args.get('search_choice')
    #print(domainUUID)
    #print(search_choice)
    if search_choice == "vdi_search":
        endpoint = f"VirDomain/{domainUUID}"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

        flash(f'Search for [{domainUUID}] complete.', 'success')
    elif search_choice == "vdi_block_search":
        endpoint = f"VirDomainBlockDevice/{domainUUID}"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

        if api_result == "[]":
            api_result = f"It appears that there are no block devices present under {domainUUID}"
        flash(f'Search for block devices under [{domainUUID}] complete.', 'success')
    elif search_choice == "vdi_stats_search":
        endpoint = f"VirDomainStats/{domainUUID}"
        url2use = f"https://{host}/rest/v1/{endpoint}"
        method = "GET"
    
        command = f'curl -s --cookie "{cookie_value}" -X {method} {url2use}  -H "accept: application/json" | jq'
        print(f"Sending a request to {url2use}..")
        api_result = os.popen(command).read()

        if api_result == "[]":
            api_result = f"It appears that there are no statistics present under {domainUUID}"
        elif "cpuUsage" in api_result:

            data = json.loads(api_result)
            general_info = []
            detailed_info = []
            for item in data:
                general_info.append({
                    'UUID': item.get('uuid'),
                    'CPU Usage': item.get('cpuUsage'),
                    'RX Bit Rate': item.get('rxBitRate'),
                    'TX Bit Rate': item.get('txBitRate')
                })

                vsd_stats = item.get('vsdStats', [])
                for vsd_stat in vsd_stats:
                    vsd_uuid = vsd_stat.get('uuid')
                    rates = vsd_stat.get('rates', [])
                    for rate in rates:
                        detailed_info.append({
                            'VSD UUID': vsd_uuid,
                            'Decay Seconds': rate.get('decaySeconds'),
                            'Milli Reads Per Second': rate.get('millireadsPerSecond'),
                            'Milli Writes Per Second': rate.get('milliwritesPerSecond'),
                            'Read KiB/s': rate.get('readKibibytesPerSecond'),
                            'Write KiB/s': rate.get('writeKibibytesPerSecond'),
                            'Mean Read Size Bytes': rate.get('meanReadSizeBytes'),
                            'Mean Write Size Bytes': rate.get('meanWriteSizeBytes'),
                            'Mean Read Latency (μs)': rate.get('meanReadLatencyMicroseconds'),
                            'Mean Write Latency (μs)': rate.get('meanWriteLatencyMicroseconds'),
                        })

            # Create DataFrames
            df_general = pd.DataFrame(general_info)
            df_detailed = pd.DataFrame(detailed_info)

            # Combine the DataFrames
            df_combined = pd.concat([df_general, df_detailed], axis=1)

            # Transpose the combined DataFrame to have labels vertically
            df_transposed = df_combined.T
            z = df_transposed.to_string(header=False)
            #z = df.to_string(index=False)
            # Print the DataFrame as a neat table
            print(df_transposed.to_string(header=False))
            #print(df.to_string(index=False))
            api_result = f"{z}"
        flash(f'Search for Stats on [{domainUUID}] complete.', 'success')

    else:
        api_result == "NOT YET IMPLMENTED"
    return render_template('pubdocs/net/scale_api.html', result=api_result)

