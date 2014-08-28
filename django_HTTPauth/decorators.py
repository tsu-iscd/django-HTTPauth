
class policy_name_protection():
    def __init__(self,name_protection):
        self.np=name_protection
        
    def __call__(self,target): 
        try:
            if target.policy.has_key('name_protection')==True:
                if target.policy.get('name_protection')==False and self.np==True:
                    target.policy['name_protection']=self.np
            else:
                target.policy['name_protection']=self.np
        except AttributeError:
            target.policy={'name_protection':self.np}
        return target
    

class policy_replay_protection():
    def __init__(self,replay_time,replay_protection=True):
        self.rp=replay_protection
        if type(replay_time) is int:
            if replay_time>0:
                self.rt=replay_time
            else:
                self.rt=0
        elif replay_time.isdigit() == True:
            self.rt=int(replay_time)
        else:
            self.rt=0
            self.rp=False
        
    def __call__(self,target): 
        try:
            if target.policy.has_key('replay_protection')==True:
                    target.policy['replay_protection']['enable']=self.rp
                    target.policy['replay_protection']['interval']=self.rt
            else:
                target.policy['replay_protection']={'enable':self.rp,'interval':self.rt}
        except AttributeError:
            target.policy={'replay_protection':{'enable':self.rp,'interval':self.rt}}
        return target
    

class policy():
    def __init__(self,**kwargs):
        self.__dict__.update(kwargs)
        
    def __call__(self,target):
        tmp_pol = {}
        for x in self.__dict__.keys():
            if len(self.__dict__[x])==1 and isinstance(self.__dict__[x][0],str)==True:
                if self.__dict__[x][0].lower()=='control' or self.__dict__[x][0].lower()=='c':
                    tmp_pol[x]={'action':'control',}
                elif self.__dict__[x][1].lower()=='control' or self.__dict__[x][1].lower()=='c':
                    tmp_pol[x]={'action':'control',}      
            elif len(self.__dict__[x])==2 and isinstance(self.__dict__[x][0],str)==True or isinstance(self.__dict__[x][1],str)==True:
                if self.__dict__[x][0].lower()=='validate' or self.__dict__[x][0].lower()=='v':
                    tmp_pol[x]={'action':'validate','value':self.__dict__[x][1]}
                elif self.__dict__[x][1].lower()=='validate' or self.__dict__[x][1].lower()=='v':
                    tmp_pol[x]={'action':'validate','value':self.__dict__[x][0]}
        try:
            if target.policy.has_key('parameter_protection')==True:
                target.policy['parameter_protection'].update(tmp_pol)
            else:
                target.policy['parameter_protection']=tmp_pol
        except AttributeError:
            target.policy={'parameter_protection':tmp_pol}
        return target
