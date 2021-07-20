from flask import Flask, request, jsonify
import base64

admission_controller = Flask(__name__)

@admission_controller.route('/validate/certificates', methods=['POST'])
def deployment_webhook():
    request_info = request.get_json()

    try:
        if request_info["request"]["object"]["spec"]["privateKey"].get("rotationPolicy") == "Always":
            return admission_response(True, "Private key always set to rotate")
    except KeyError:
        return admission_response(False, "rotationPolicy not set")
    
    return admission_response(False, "rotationPolicy not set to Always")
def admission_response(allowed, message):
    return jsonify({"response": {"allowed": allowed, "status": {"message": message}}})


@admission_controller.route('/mutate/certificates', methods=['POST'])
def deployment_webhook_mutate():
    request_info = request.get_json()

    # patchs to apply
    patch_list = []
    spec = request_info["request"]["object"]["spec"]

    # add the privateKey patch and values if not set
    if "privateKey" not in spec:
        patch_list.append('{"op": "replace", "path": "/spec/privateKey", "value": {"rotationPolicy": "Always"}}')
    # else just replace the specific value if it's not set correctly
    elif "rotationPolicy" not in spec["privateKey"] or spec["privateKey"]["rotationPolicy"] != "Always":
        patch_list.append('{"op": "replace", "path": "/spec/privateKey/rotationPolicy", "value": "Always"}')
    
    # join patch list into json object
    patches = "[" + ",".join(patch_list) + "]"

    # base64 the patch for use in http response 
    base64_patch = base64.b64encode(patches.encode("utf-8")).decode("utf-8")

    # set warnings if change applied
    warnings = []
    if len(patch_list) > 0:
        warnings = ["Set privateKey rotationPolicy to Always per policy"]

    # send response
    return jsonify({"response": {"allowed": True,
                                 "warnings": warnings,
                                 "patchType": "JSONPatch",
                                 "patch": base64_patch}})

if __name__ == '__main__':
    admission_controller.run(host='0.0.0.0', port=443, ssl_context=("/app/server.crt", "/app/server.key"))