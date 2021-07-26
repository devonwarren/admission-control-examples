from flask import Flask, request, jsonify
from os import getenv

admission_controller = Flask(__name__)

@admission_controller.route('/validate/network-policy', methods=['POST'])
def validating_webhook():
    log = admission_controller.logger
    # parse request info into array
    request_info = request.get_json()

    # print full request object when in debug mode
    log.debug("Request input received: " + str(request_info))
    
    op = request_info["request"]["operation"]
    name = request_info["request"]["oldObject"]["metadata"]["name"]

    
    # allow runtime overriding of exempted user
    adminUser = getenv("ALLOWED_USER", "kubernetes-admin")
    # exempt PRM system user from not being able to delete
    if request_info["request"]["userInfo"]["username"] == adminUser:
        log.info("User '%s' exempted for request on netpol '%s'", adminUser, name)
        return admission_response(True, "User exempted from network policy modification restrictions")

    # only restrict the default-deny network policy
    if name == "default-deny":
        if op == "DELETE":
            log.warning("Blocking attempt to delete netpol '%s'", name)
            return admission_response(False, "Cannot delete default network policy")
        elif op == "UPDATE":
            log.warning("Blocking attempt to update netpol '%s'", name)
            return admission_response(False, "Cannot change the default network policy, you can add exemptions with addition policies")

    # if it makes it to here it must be allowed
    log.debug("Modification allowed for netpol '%s'", name)
    return admission_response(True, "Network policy modification allowed")
    
def admission_response(allowed, message):
    return jsonify({"response": {"allowed": allowed, "status": {"message": message}}})

if __name__ == '__main__':
    # if debug is set in deployment env, set that at runtime
    debug = False
    if getenv("DEBUG", "false").lower() == "true":
        debug = True
    
    admission_controller.run(host='0.0.0.0', port=443, ssl_context=("/app/ssl/tls.crt", "/app/ssl/tls.key"), debug=debug)