
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
    