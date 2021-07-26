from flask import Flask, request, jsonify
from os import getenv

admission_controller = Flask(__name__)

@admission_controller.route('/validate/webhook', methods=['POST'])
def validating_webhook():
    log = admission_controller.logger
    # parse request info into array
    request_info = request.get_json()

    # print full request object when in debug mode
    log.debug("Request input received: " + str(request_info))
    
    # check ingress hosts don't have wildcards
    for rule in request_info["request"]["object"]["spec"]["rules"]:
      if "*" in rule["host"]:
        log.warning("Blocking attempt to add ingress host '%s'", rule["host"])
        return admission_response(False, "Cannot create ingress hosts with wildcard")
    
    # if it makes it to here it must be allowed
    log.debug("Modification allowed for ingress '%s'", request_info["request"]["name"])
    return admission_response(True, "Ingress modification allowed")
    
def admission_response(allowed, message):
    return jsonify({"response": {"allowed": allowed, "status": {"message": message}}})

if __name__ == '__main__':
    # if debug is set in deployment env, set that at runtime
    debug = False
    if getenv("DEBUG", "false").lower() == "true":
        debug = True
    
    admission_controller.run(host='0.0.0.0', port=443, ssl_context=("/app/ssl/tls.crt", "/app/ssl/tls.key"), debug=debug)