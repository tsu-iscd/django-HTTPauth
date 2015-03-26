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

    if 'sess_key' not in request.session.keys():
        return False 

    tokens = base64.b64decode(token).split(';')
    
    if len(tokens) == 1:
        if token in request.session['csrf_tokens']:
            request.session['csrf_tokens'].remove(token)
            return True
        return False
    
    if len(tokens) != 2:
        return False

    policy = {}
    sts=tokens[1]

    fl_np = [k for k in dic_all]
    fl_np.sort()
    
    for ipolid in request.session['forms'].keys():
        polid = ipolid[1:]
        if ipolid[0] == '0':
            if re.sub(base64.b64decode(polid),'#',request.build_absolute_uri())=='#':
                policy = request.session['forms'][ipolid]['policy']
                objid = ipolid
        elif ipolid[0] == '1':
            if base64.b64decode(polid)=='&'.join(fl_np):
                policy = request.session['forms'][ipolid]['policy']
                objid = ipolid
        elif ipolid[0] == '2':
            polid_url,polid_params=polid.split(';')
            if re.sub(base64.b64decode(polid_url),'#',request.build_absolute_uri())=='#' and base64.b64decode(polid_params)=='&'.join(fl_np):
                policy = request.session['forms'][ipolid]['policy']
                objid = ipolid


    if len(policy)==0:
        for k in request.session['csrf_tokens']:
            if k == token:
                request.session['csrf_tokens'].remove(k)
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
    
    if ncont == True:
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
            if subid=='' or subid==None:
                subid=request.session.session_key
    except KeyError:
        return False

    res_token =res_str+';'+sts+';'+objid+';'+subid+';'+request.method
    sc_tok = sfunc_mess(base64.b64decode(request.session['sess_key']),res_token,';'+sts)
    
    if sc_tok == token:
        return True

    return False


def sfunc_mess(key,message,tstamp):
    shash = hmac.new(key,msg=message,digestmod=hashlib.sha256).digest()
    return base64.b64encode(shash+tstamp).decode()


def auth_render(request, *args, **kwargs):
    if not request.session.exists(request.session.session_key):
        request.session.create()
    request.session['forms']={}
    request.session['csrf_tokens']=[]
    for cont in args:
        if type(cont) is dict:
            for key in cont:
                if issubclass(cont[key].__class__,forms.ModelForm)==True or issubclass(cont[key].__class__,forms.Form)==True:
                    f = cont[key]

                    try:

                        tstamp = ';'+str(int(round(time.time()*1000)))
                        
                        if 'sess_key' not in request.session.keys():
                            rndfile = Random.new()
                            gen_key = rndfile.read(BLOCK_SIZE)
                            request.session['sess_key'] = base64.b64encode(gen_key)

                        lf_all = []
                        for x in f.fields:
                            lf_all.append(x)
                        lf_all.sort()
                        
                        policy_id = None

                        obj_id=None
                        if f.policy.has_key('object_id')==True:
                            obj_id_str=f.policy.get('object_id')
                            if obj_id_str == 'url':
                                obj_id=0
                                policy_id=str(obj_id)+base64.b64encode(f.policy['object'])
                            elif obj_id_str == 'parameters' or obj_id_str == 'params':
                                obj_id=1
                                policy_id=str(obj_id)+base64.b64encode('&'.join(lf_all))
                            else:
                                obj_id=2
                                policy_id=str(obj_id)+base64.b64encode(f.policy['object'])+';'+base64.b64encode('&'.join(lf_all))
                        else:
                            obj_id=1
                            policy_id=str(obj_id)+base64.b64encode('&'.join(lf_all))

                        if obj_id is None:
                            res_token = get_random_string(SCSRF_RAND_LENGTH)
                            f.fields["auth_token"]= forms.CharField(widget=forms.HiddenInput,max_length=len(res_token),initial=res_token)
                            request.session['csrf_tokens'].append(res_token)
                        
                        res_str = ''
                        if f.policy.get('name_protection') == True:
                            res_str = '&'.join(lf_all)
                            res_str+=';'

                        fl_val = []
                        for fl in f.policy['parameter_protection']:
                            if f.policy['parameter_protection'][fl]['action'] == 'validate':
                                fl_val.append(fl+'=#')
                            elif f.policy['parameter_protection'][fl]['action']=='control':
                                try:
                                    fl_val.append(fl+'='+f.initial[fl])
                                except KeyError:
                                    print(fl+' field is not under control')

                        fl_val.sort()
                        
                        if policy_id not in request.session['forms']: 
                            request.session['forms'][policy_id]={'policy':f.policy,}
                        res_str+='&'.join(fl_val)

                        try:
                            subid = ''
                            if f.policy.has_key('subject')==True:
                                subid = request.COOKIES[f.policy['subject']]
                            else:
                                subid = request.COOKIES [settings.SESSION_COOKIE_NAME]
                                if subid=='' or subid==None:
                                    subid=request.session.session_key
                        except KeyError:
                            if not request.session.exists(request.session.session_key):
                                request.session.create()
                                subid=request.session.session_key

                        res_token=res_str+tstamp+';'+policy_id+';'+subid+';POST'


                        sc_tok = sfunc_mess(base64.b64decode(request.session['sess_key']),res_token,tstamp)
                        f.fields["auth_token"]= forms.CharField(widget=forms.HiddenInput,max_length=len(sc_tok),initial=sc_tok)
                    except AttributeError:
                        res_token = get_random_string(SCSRF_RAND_LENGTH)
                        f.fields["auth_token"]= forms.CharField(widget=forms.HiddenInput,max_length=len(res_token),initial=res_token)
                        request.session['csrf_tokens'].append(res_token)
                        	
    return render(request, *args, **kwargs)


