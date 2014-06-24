from django.shortcuts import render, render_to_response
from django import forms
from django.utils.crypto import get_random_string
from django.conf import settings

import hashlib
import hmac
import simplejson
import re
import base64

from Crypto.Cipher import AES
from Crypto import Random

import time
SCSRF_RAND_LENGTH = 16

BLOCK_SIZE = 16

def token_validate(request,token,dic_all):

    if len(dic_all)==0:
        return False

    policy = {}
    b_key = ''
    sts=''

    for polid in request.session['forms'].keys():
        if re.sub(base64.b64decode(polid),'#',request.build_absolute_uri())=='#':
            policy = request.session['forms'][polid]['policy']
            b_key = request.session['forms'][polid]['auth_key']
            sts = request.session['forms'][polid]['time']
            objid = polid


    if len(policy)==0 and len(b_key)==0:
        for k in request.session['csrf_tokens']:
            if k == token:
                return True
        return False

    ncont=policy['name_protection']
    rprot = policy['replay_protection']
    res_str = ''

    if rprot['enable']==True:
        time_interval = rprot['interval']
        tstamp = int(sts) 
        if int(round(time.time()*1000)) - tstamp >= int(time_interval*1000):
            return False
    
    fl_np = []
    if ncont == True:
        fl_np = [k for k in dic_all]
        fl_np.sort()
        res_str += '&'.join(fl_np)+';'

    fl_val = []
    for fl in policy['parameter_protection']:
        if policy['parameter_protection'][fl]['action'] == 'validate':
            try:
                val_res = re.sub(policy['parameter_protection'][fl]['value'],'#',dic_all[fl])
                fl_val.append(fl+'='+val_res)
            except KeyError:
                return False
        elif policy['parameter_protection'][fl]['action']=='control':
            try:
                fl_val.append(fl+'='+dic_all[fl])
            except KeyError:
                return False
 
    fl_val.sort()
    res_str+='&'.join(fl_val)

    try:
        subid = ''
        if policy.has_key('subject')==True:
            subid = request.COOKIES[policy['subject']]
        else:
            subid = request.COOKIES[settings.SESSION_COOKIE_NAME]
    except KeyError:
        return False

    res_token =res_str+';'+sts+';'+objid+';'+subid+';'+request.method

    sc_tok = sfunc_mess(base64.b64decode(b_key),res_token)
    
    if sc_tok == token:
        return True

    return False


def sfunc_mess(key,message):
    shash = hmac.new(key,msg=message,digestmod=hashlib.sha256).digest()
    return base64.b64encode(shash).decode()


def auth_render(request, *args, **kwargs):
    request.session['forms']={}
    request.session['csrf_tokens']=[]
    for cont in args:
        if type(cont) is dict:
            for key in cont:
                if issubclass(cont[key].__class__,forms.ModelForm)==True or issubclass(cont[key].__class__,forms.Form)==True:
                    f = cont[key]

                    try:

                        tstamp=''
                        if f.policy.get('replay_protection')['enable']==True:
                            tstamp = ';'+str(int(round(time.time()*1000)))
                        rndfile = Random.new()
                        gen_key = rndfile.read(BLOCK_SIZE)
                        b_key=base64.b64encode(gen_key)

                        lf_all = []
                        for x in f.fields:
                            lf_all.append(x)
                        lf_all.sort()
                        
                        res_str = ''
                        if f.policy.get('name_protection') == True:
                            res_str = '&'.join(lf_all)
                            res_str+=';'

                        fl_val = []
                        for fl in f.policy['parameter_protection']:
                            if f.policy['parameter_protection'][fl]['action'] == 'validate':
                                fl_val.append(fl+'=#')
                            elif f.policy['parameter_protection'][fl]['action']=='control':
                                fl_val.append(fl+'='+f.policy['parameter_protection'][fl]['value'])

                        fl_val.sort()

                        request.session['forms'][base64.b64encode(f.policy['object'])]={'policy':f.policy,'auth_key':b_key,'time':tstamp[1:]}                        
                        res_str+='&'.join(fl_val)

                        try:
                            subid = ''
                            if f.policy.has_key('subject')==True:
                                subid = request.COOKIES[f.policy['subject']]
                            else:
                                subid = request.COOKIES[settings.SESSION_COOKIE_NAME]
                        except KeyError:
                            if not request.session.exists(request.session.session_key):
                                request.session.create()
                                subid=request.session.session_key

                        res_token=res_str+tstamp+';'+base64.b64encode(f.policy['object'])+';'+subid+';POST'


                        sc_tok = sfunc_mess(gen_key,res_token)
                        f.fields["auth_token"]= forms.CharField(widget=forms.HiddenInput,max_length=len(sc_tok),initial=sc_tok)
                    except AttributeError:
                        res_token = get_random_string(SCSRF_RAND_LENGTH)
                        f.fields["auth_token"]= forms.CharField(widget=forms.HiddenInput,max_length=len(res_token),initial=res_token)
                        request.session['csrf_tokens'].append(res_token)
                        	
    return render(request, *args, **kwargs)


