import sys
import os

sys.path.append(f"{os.environ['LAMBDA_TASK_ROOT']}/lib")
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

import cr_response
from logic import WafRateLimit
import json

def lambda_handler(event, context):

    print(f"Received event:{json.dumps(event)}")

    lambda_response = cr_response.CustomResourceResponse(event)
    cr_params = event['ResourceProperties']
    waf_logic = WafRateLimit(cr_params)
    try:
        # if create request, generate physical id, both for create/update copy files
        if event['RequestType'] == 'Create':
            event['PhysicalResourceId'] = waf_logic._create_rate_based_rule()
            data = {
                "RuleID" : event['PhysicalResourceId']
            }
            lambda_response.respond(data)

        elif event['RequestType'] == 'Update':
            waf_logic._update_rate_based_rule(event['PhysicalResourceId'])
            data = {
                "RuleID" : event['PhysicalResourceId']
            }
            lambda_response.respond(data)

        elif event['RequestType'] == 'Delete':
            print(event['PhysicalResourceId'])
            waf_logic._delete_rate_based_rule(event['PhysicalResourceId'])
            data = { }
            lambda_response.respond(data)

    except Exception as e:
        message = str(e)
        lambda_response.respond_error(message)

    return 'OK'
