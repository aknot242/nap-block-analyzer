# Transparent Policy Block Analyzer

What does it do? Have you ever wanted to run NGINX App Protect in transparent mode, and be able to determine what requests _would_ be blocked if it were in blocking mode? Now you can.

This utility receives App Protect WAF's syslog messages and performs analysis to determine if your requests would be blocked given your specific policy. 

## Requirements
- NGINX App Protect WAF 3.3 or greater (the policy export utility is required)
- NodeJS and NPM
- A Websockets capable browser
- An exported signature report file (in JSON format) from your App Protect WAF instance involved in the test
- Your App Protect WAF policy file, exported in "full" (verbose) format
- Docker and Docker Compose if you want to use the test containers

## How to use

Install NGINX App Protect WAF using the [instructions](https://docs.nginx.com/nginx-app-protect/admin-guide/install/) appropriate for your environment. It is recommended to install the latest Attack Signatures and Threat Campaigns packages.

### Export the Signatures to a file
```
/opt/app_protect/bin/get-signatures -o /tmp/signature-report.json
```

Then, copy the contents of `/tmp/signature-report.json` to the example `signature-report.json` file in this folder.

### Export your effective NAP policy:
```
/opt/app_protect/bin/convert-policy -i <full path to your policy here>  -o /tmp/full-policy-export.json --full-export
```

Then, copy the contents of `/tmp/full-policy-export.json` to the example `full-policy-export.json` file in this folder.

### Configure your App Protect WAF Log policy file
Edit your App Protect Log policy file so it contains the following format:

``` json
{
    "filter": {
        "request_type": "illegal"
    },
    "content": {
        "format": "user-defined",
        "format_string": "naphost nginx-app-protect: {\"clientIp\": \"%ip_client%\", \"botCategory\": \"%bot_category\", \"botSignatureName\": \"%bot_signature_name%\", \"clientClass\": \"%client_class%\",\"violations\": \"%violations%\", \"signatureIds\": [%sig_ids%], \"supportId\": \"%support_id%\", \"violationDetails\": \"%violation_details%\" }",
        "max_request_size": 2000,
        "max_message_size": "10k"
    }
}
```

If you want to use the nikto scanner to test this solution, you will have to trust its user agent by adding this to your WAF policy:
``` json
"bot-defense": {
    "isEnabled": true,
    "mitigations": {
      "signatures": [
        {
          "name": "nikto",
          "action": "detect"
        }
      ]
    }
  }
```

### Add the required NGINX conf configuration
```
app_protect_security_log "<location of log policy file above>" syslog:server=host.docker.internal:5144;
```

### Install the Node app's dependencies
```
npm install
```

### Start the block analyzer node app
```
npm start
```

### Optional: Create Test Containers
If you want to run this locally, there is a Docker Compose located in this repo to build and serve an NGINX App Protect instance protecting a sample application (Juice Shop). You need to provide a valid `nginx-repo.crt` and `nginx-repo.key` in the `test` directory.

```
cd test
docker-compose up -d 
```

### Open the app in your browser
Navigate to `http://localhost:6969`


### Generate Chaos
```
docker run --rm frapsoft/nikto -h http://host.docker.internal
```

## Attributions
Special thanks to [Lior Moscovici](https://github.com/liorm39) for documenting the block determination logic and his support.
