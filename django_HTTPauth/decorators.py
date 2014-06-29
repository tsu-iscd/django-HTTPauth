
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
                target.policy['name_protection']={'enable':self.rp,'interval':self.rt}
        except AttributeError:
            target.policy={'name_protection':{'enable':self.rp,'interval':self.rt}}
        return target