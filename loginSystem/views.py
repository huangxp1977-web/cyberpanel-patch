# -*- coding: utf-8 -*-


from django.shortcuts import render, redirect
from .models import Administrator
from plogical import hashPassword
import json
from packages.models import Package
from baseTemplate.models import version
from plogical.getSystemInformation import SystemInformation
from .models import ACL
from plogical.acl import ACLManager
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import HttpResponse
# Create your views here.

VERSION = '2.4'
BUILD = 4


def check2FAStatus(request):
    """
    API endpoint to check if a user has 2FA enabled
    Returns: {'has2FA': true/false}
    """
    try:
        data = json.loads(request.body)
        username = data.get('username', '')
        
        if not username:
            return HttpResponse(json.dumps({'has2FA': False}))
        
        try:
            admin = Administrator.objects.get(userName=username)
            return HttpResponse(json.dumps({'has2FA': bool(admin.twoFA)}))
        except Administrator.DoesNotExist:
            return HttpResponse(json.dumps({'has2FA': False}))
    except:
        return HttpResponse(json.dumps({'has2FA': False}))


def verifyLogin(request):
    try:
        userID = request.session['userID']
        data = {'userID': userID, 'loginStatus': 1, 'error_message': "None"}
        json_data = json.dumps(data)
        return HttpResponse(json_data)
    except KeyError:
        username = "not logged in"
        password = ""

        try:
            if request.method == "POST":
                try:
                    data = json.loads(request.body)
                except json.JSONDecodeError:
                    data = {'userID': 0, 'loginStatus': 0, 'error_message': 'Invalid request format'}
                    json_data = json.dumps(data)
                    return HttpResponse(json_data)

                username = data.get('username', '')
                password = data.get('password', '')

            admin = Administrator.objects.get(userName=username)

            if admin.state == 'SUSPENDED':
                data = {'userID': 0, 'loginStatus': 0, 'error_message': 'Account currently suspended.'}
                json_data = json.dumps(data)
                return HttpResponse(json_data)

            password_check_result = hashPassword.check_password(admin.password, password)

            if password_check_result:
                # Check if 2FA is enabled and validate if code provided
                if admin.twoFA:
                    import pyotp
                    totp = pyotp.TOTP(admin.secretKey)
                    twofa_code = data.get('twofa', '')
                    if not twofa_code or str(totp.now()) != str(twofa_code):
                        data = {'userID': 0, 'loginStatus': 0, 'error_message': "Invalid verification code."}
                        json_data = json.dumps(data)
                        return HttpResponse(json_data)

                # Login successful
                request.session['userID'] = admin.pk

                ipAddr = request.META.get('HTTP_CF_CONNECTING_IP')
                if ipAddr is None:
                    ipAddr = request.META.get('REMOTE_ADDR')

                if ipAddr.find(':') > -1:
                    ipAddr = ':'.join(ipAddr.split(':')[:3])
                    request.session['ipAddr'] = ipAddr
                else:
                    request.session['ipAddr'] = ipAddr

                request.session.set_expiry(43200)
                data = {'userID': admin.pk, 'loginStatus': 1, 'error_message': "None"}
                json_data = json.dumps(data)
                return HttpResponse(json_data)

            else:
                data = {'userID': 0, 'loginStatus': 0, 'error_message': "login failed."}
                json_data = json.dumps(data)
                return HttpResponse(json_data)

        except BaseException as msg:
            data = {'userID': 0, 'loginStatus': 0, 'error_message': str(msg)}
            json_data = json.dumps(data)
            return HttpResponse(json_data)

@ensure_csrf_cookie
def loadLoginPage(request):
    try:
        userID = request.session['userID']
        currentACL = ACLManager.loadedACL(userID)

        cpuRamDisk = SystemInformation.cpuRamDisk()

        if currentACL['admin'] == 1:
            admin = 1
        else:
            admin = 0

        finaData = {"admin": admin, 'ramUsage': cpuRamDisk['ramUsage'], 'cpuUsage': cpuRamDisk['cpuUsage'],
                    'diskUsage': cpuRamDisk['diskUsage']}

        from baseTemplate.views import renderBase
        return redirect(renderBase)

        #return render(request, 'baseTemplate/homePage.html', finaData)
    except KeyError:
        from firewall.models import FirewallRules

        numberOfAdministrator = Administrator.objects.count()
        password = hashPassword.hash_password('1234567')
        noOfRules = FirewallRules.objects.count()

        if noOfRules == 0:
            newFWRule = FirewallRules(name="panel", proto="tcp", port="8090")
            newFWRule.save()

            newFWRule = FirewallRules(name="http", proto="tcp", port="80")
            newFWRule.save()

            newFWRule = FirewallRules(name="https", proto="tcp", port="443")
            newFWRule.save()

            newFWRule = FirewallRules(name="ftp", proto="tcp", port="21")
            newFWRule.save()

            newFWRule = FirewallRules(name="smtp", proto="tcp", port="25")
            newFWRule.save()

            newFWRule = FirewallRules(name="smtps", proto="tcp", port="587")
            newFWRule.save()

            newFWRule = FirewallRules(name="ssmtp", proto="tcp", port="465")
            newFWRule.save()

            newFWRule = FirewallRules(name="pop3", proto="tcp", port="110")
            newFWRule.save()

            newFWRule = FirewallRules(name="imap", proto="tcp", port="143")
            newFWRule.save()

            newFWRule = FirewallRules(name="simap", proto="tcp", port="993")
            newFWRule.save()

            newFWRule = FirewallRules(name="dns", proto="udp", port="53")
            newFWRule.save()

            newFWRule = FirewallRules(name="dnstcp", proto="tcp", port="53")
            newFWRule.save()

            newFWRule = FirewallRules(name="ftptls", proto="tcp", port="40110-40210")
            newFWRule.save()

            newFWRule = FirewallRules(name="POP3S", proto="tcp", port="995")
            newFWRule.save()

            newFWRule = FirewallRules(name="quic", proto="udp", port="443")
            newFWRule.save()

        if numberOfAdministrator == 0:
            ACLManager.createDefaultACLs()
            acl = ACL.objects.get(name='admin')

            token = hashPassword.generateToken('admin', '1234567')

            email = 'admin@cyberpanel.net'
            admin = Administrator(userName="admin", password=password, type=1, email=email,
                                  firstName="Cyber", lastName="Panel", acl=acl, token=token)
            admin.save()

            vers = version(currentVersion=VERSION, build=BUILD)
            vers.save()

            package = Package(admin=admin, packageName="Default", diskSpace=1000, bandwidth=1000, ftpAccounts=1000,
                              dataBases=1000, emailAccounts=1000, allowedDomains=20)
            package.save()

            ### Load Custom CSS
            try:
                from baseTemplate.models import CyberPanelCosmetic
                cosmetic = CyberPanelCosmetic.objects.get(pk=1)
            except:
                from baseTemplate.models import CyberPanelCosmetic
                cosmetic = CyberPanelCosmetic()
                cosmetic.save()

            return render(request, 'loginSystem/login.html', {'cosmetic': cosmetic})
        else:
            ### Load Custom CSS
            try:
                from baseTemplate.models import CyberPanelCosmetic
                cosmetic = CyberPanelCosmetic.objects.get(pk=1)
            except:
                from baseTemplate.models import CyberPanelCosmetic
                cosmetic = CyberPanelCosmetic()
                cosmetic.save()
            return render(request, 'loginSystem/login.html', {'cosmetic': cosmetic})


@ensure_csrf_cookie
def logout(request):
    try:
        del request.session['userID']
        return render(request, 'loginSystem/login.html', {})
    except:
        return render(request, 'loginSystem/login.html', {})
