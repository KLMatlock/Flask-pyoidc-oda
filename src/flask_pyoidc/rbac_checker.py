# postponed evaluation of annotation
from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


VALID_SOURCE = ['auth', 'id', 'userinfo']

class RBACChecker:
    is_set = True

    def __init__(self, roles_required :  list[str] = [], claim = 'roles', source = 'userinfo'):
        if roles_required == []:
            self.is_set = False
            return

        if source not in VALID_SOURCE:
            raise ValueError(f"Source must be one of {VALID_SOURCE}")
        self.source = source
        self.claim = claim
        self.roles_requires = roles_required
        

    def check_rbac(self, auth_token = {}, id_token = {}, userinfo_token = {}) -> bool:
        """Check for role claims against provided tokens.

        Parameters
        ----------
        auth_token : dict, optional
            Authorization token, by default {}
        id_token : dict, optional
            ID token, by default {}
        userinfo_token : dict, optional
            Userinfo token, by default {}
        """     

        if self.is_set == False:
            logger.debug("No role check performed.")
            return True   

        claims = {}
        # Extract appropriate claim source.
        if self.source == VALID_SOURCE[0]: #auth
            claims = auth_token
        elif self.source == VALID_SOURCE[1]: #id
            claims = id_token
        elif self.source == VALID_SOURCE[2]: #userinfo
            claims = userinfo_token

        if claims == {}:
            raise ValueError(f"No claim data passed for source {self.source}")
        logger.debug(f"Checking claim in source {self.source}")
        
        if "." in self.claim:
            source_claim_ls = self.claim.split(".")
        else:
            source_claim_ls = [self.claim]
        try:
            claim = claims[source_claim_ls.pop(0)]
            while source_claim_ls != []:
                claim = claim[source_claim_ls.pop(0)]
            logger.debug(f"Roles assigned to user {claim}")
        except KeyError:
            logger.debug("Claim not found. Not authorizing user.")
            return False

        if not isinstance(claim, list):
            claim = [claim]
        
        if(set(self.roles_requires).issubset(set(claim))):
            return True
        return False
