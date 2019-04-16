import boto3
import os
import glob
import logging
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class WafRateLimit:

    def __init__(self, resource_properties):
        self.rate = resource_properties['Rate']
        self.action = resource_properties['Action']
        self.region = resource_properties['Region']
        self.ip_set = resource_properties['IPSet']
        self.negated = resource_properties['Negated']
        self.region = resource_properties['Region']
        self.regional = resource_properties.get('Regional', 'false')
        self.web_acl_id = resource_properties['WebACLId']
        self.priority = int(resource_properties['Priority'])

        if 'EnvironmentName' in resource_properties:
            self.rule_name = f"{resource_properties['EnvironmentName']}-rate-limit"
            self.ip_set_name = f"{resource_properties['EnvironmentName']}-rate-limit-ip-set"
        else:
            self.rule_name = resource_properties['RuleName']
            self.ip_set_name = resource_properties['IpSetName']

        self.metric_name = self.rule_name.replace('-', '')

        if to_bool(self.regional):
            self.client = boto3.client('waf-regional', region_name=self.region)
        else:
            self.client = boto3.client('waf', region_name=self.region)

    def retry(func):
        # Reattempt to execute a given function with optional arguments.
        # This is to avoid the insane error about a token already being expired.
        def wrapper(self, *args, **kwargs):
            attempts = 5
            remaining = attempts

            while remaining:
                try:
                    result = func(self, *args, **kwargs)
                    return result
                except self.client.exceptions.WAFStaleDataException as e:
                    logger.info(str(e))
                    time.sleep(1)
                    logger.info("(%d/%d) Retrying request with a new change token..." % (remaining + 1, attempts))
                    remaining -= 1

            logger.info("ERROR - failed to execute request.")
            exit(1)

        return wrapper

    def _create_rate_based_rule(self):
        rule_id = self.create_rate_based_rule()

        if len(self.ip_set):
            ip_set_id = self.create_ip_set()
            self.update_ip_set('INSERT', ip_set_id, self.ip_set)
            self.update_rate_based_rule('INSERT', ip_set_id, rule_id)

        self._add_to_web_acl(rule_id)

        return rule_id

    @retry
    def create_rate_based_rule(self):
        change_token = self._get_change_token()
        logger.info("Creating WAF rule '%s' ..." % self.rule_name)

        rule_id = self.client.create_rate_based_rule(
            Name=self.rule_name,
            MetricName=self.metric_name,
            RateLimit=int(self.rate),
            RateKey='IP',
            ChangeToken=change_token
        )['Rule']['RuleId']

        return rule_id

    @retry
    def create_ip_set(self):
        change_token = self._get_change_token()
        logger.info("Creating IP set '%s' ..." % self.ip_set_name)

        ip_set_id = self.client.create_ip_set(
            Name=self.ip_set_name,
            ChangeToken=change_token
        )['IPSet']['IPSetId']

        return ip_set_id

    @retry
    def update_ip_set(self, action, ip_set_id, ip_set):
        change_token = self._get_change_token()
        logger.info("Updating IP set '%s' (%s) with %d IPs as %s ..." % (self.ip_set_name, ip_set_id, len(self.ip_set), action))

        self.client.update_ip_set(
            IPSetId=ip_set_id,
            ChangeToken=change_token,
            Updates=generate_waf_ip_set(action, ip_set)
        )

    def _update_rate_based_rule(self, rule_id):
        self._delete_rate_based_rule(rule_id)
        return self._create_rate_based_rule()

    @retry
    def update_rate_based_rule(self, action, ip_set_id, rule_id):
        change_token = self._get_change_token()
        logger.info("Updating rule '%s' (%s) with IP set '%s' (%s) as %s ..." % (self.rule_name, rule_id, self.ip_set_name, ip_set_id, action))

        self.client.update_rate_based_rule(
            RuleId=rule_id,
            ChangeToken=change_token,
            Updates=[{
                'Action': action,
                'Predicate': {
                    'Negated': to_bool(self.negated),
                    'Type': 'IPMatch',
                    'DataId': ip_set_id
                }
            }],
            RateLimit=int(self.rate)
        )

    def _delete_rate_based_rule(self, rule_id):
        logger.info("Getting IP set for rule '%s' (%s) ..." % (self.rule_name, rule_id))

        try:
            predicates = self.client.get_rate_based_rule(
                RuleId=rule_id
            )['Rule']['MatchPredicates']
        except self.client.exceptions.WAFNonexistentItemException as e:
            logger.info("%s: rule ID '%s' does not exist. Returning success" % (str(e), rule_id))
            return

        if len(predicates):
            ip_set_id = predicates[0]['DataId']

            logger.info("Getting IPs for IP set '%s' ..." % (ip_set_id))

            current_ip_set = self.client.get_ip_set(
                IPSetId=ip_set_id
            )['IPSet']['IPSetDescriptors']

            if len(current_ip_set):
                self.update_ip_set('DELETE', ip_set_id, current_ip_set)

            self.update_rate_based_rule('DELETE', ip_set_id, rule_id)
            self.delete_ip_set(ip_set_id)

        self._delete_from_web_acl(rule_id)
        self.delete_rate_based_rule(rule_id)

    @retry
    def delete_ip_set(self, ip_set_id):
        change_token = self._get_change_token()
        logger.info("Deleting IP set '%s' ..." % (ip_set_id))

        self.client.delete_ip_set(
            IPSetId=ip_set_id,
            ChangeToken=change_token
        )

    @retry
    def delete_rate_based_rule(self, rule_id):
        change_token = self._get_change_token()
        logger.info("Deleting rule '%s' (%s) ..." % (self.rule_name, rule_id))

        self.client.delete_rate_based_rule(
            RuleId=rule_id,
            ChangeToken=change_token
        )

    def _get_change_token(self):
        token = self.client.get_change_token()['ChangeToken']
        logger.info("Got change token: %s" % token)
        return token

    def _add_to_web_acl(self, rule_id):
        self._update_web_acl('INSERT', self.action, self.priority, rule_id)

    def _delete_from_web_acl(self, rule_id):
        # Get the current rule priority, as it is needed in the update request
        web_acl_rules = self.client.get_web_acl(
            WebACLId=self.web_acl_id
        )['WebACL']['Rules']

        current_rule = list(filter(lambda rule: rule['RuleId'] == rule_id, web_acl_rules))[0]
        current_action = current_rule['Action']['Type']
        current_priority = int(current_rule['Priority'])

        self._update_web_acl('DELETE', current_action, current_priority, rule_id)

    @retry
    def _update_web_acl(self, new_action, current_action, priority, rule_id):
        """Add a rule ID with a web ACL.
        """
        change_token = self._get_change_token()
        logger.info("%sing rule '%s' (%s) in web ACL ID '%s'" % (new_action, self.rule_name, rule_id, self.web_acl_id))

        self.client.update_web_acl(
            WebACLId=self.web_acl_id,
            Updates=[{
              "Action": new_action,
              "ActivatedRule": {
                "Action": {
                    "Type": current_action
                },
                "Priority": priority,
                "RuleId": rule_id,
                "Type": "RATE_BASED"
              }
            }],
            ChangeToken=change_token
        )

def generate_waf_ip_set(action, ips):
    return [{'Action': action, 'IPSetDescriptor': ip } for ip in ips]

def to_bool(value):
    return value.lower() == 'true'
