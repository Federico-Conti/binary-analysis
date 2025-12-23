import subprocess

def cmd_lab(request):
    if request.user.is_authenticated:
        if request.method == "POST":
            domain = request.POST.get('domain')
            domain = domain.replace("https://www.", '')
            os = request.POST.get('os')
            if os == 'win':
                command = "nslookup {}".format(domain)
            else:
                command = "dig {}".format(domain)
            try:
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                data = stdout.decode('utf-8')
                stderr = stderr.decode('utf-8')
            except Exception as e:
                data = None
                stderr = str(e)
                
                
                
"""
Un attaccante potrebbe inviare un valore malevolo per il parametro domain, ad esempio:

Eseguire comandi arbitrari:
; rm -rf / 

quidni 
nslookup example.com; rm -rf / 

"""