const XmlParser = require("fast-xml-parser")
const he = require("he")
const fs = require("fs")

let defaultPolicy = {}
let policyMessages = new Set()
let signatureDB = {}

exports.clearMessages = () => policyMessages.clear()

const SIGNATURES_FILE = "signature-report.json"
const POLICY_FILE = "full-policy-export.json"

exports.loadPolicyResources = () => {
    const sigReportPromise = fs.promises.readFile(SIGNATURES_FILE, "utf8")
    const fullDefaultPolicyPromise = fs.promises.readFile(POLICY_FILE, "utf8")

    Promise.all([sigReportPromise, fullDefaultPolicyPromise])
        .catch(error => console.log(`error file: ${error}`))
        .then(data => {
            signatureDB = JSON.parse(data[0])
            defaultPolicy = JSON.parse(data[1])
        })
}

exports.parseNapMessage = (data) => {
    data.msg = data.msg.replace("[N/A]", "[]")
    let msgJson
    try {
        msgJson = JSON.parse(data.msg)
    } catch (error) {
        console.error(`Error parsing JSON value: ${data.msg}`)
    }

    if (msgJson.clientClass.toLowerCase() === "malicious bot") {
        const maliciousBotClassSettings = defaultPolicy.policy["bot-defense"]?.mitigations?.classes?.find(botclass => botclass.name?.toLowerCase() === "malicious-bot")
        const botSig = defaultPolicy.policy["bot-defense"]?.mitigations?.signatures?.find(sig => sig.name === msgJson.botSignatureName)
        // if the default for malicious bot class is "block"
        // AND if there is no exception for the malicious bot in the policy, it will be blocked
        // OR if it IS defined in there and is explicitly set to action = block, it will be blocked
        if (maliciousBotClassSettings?.action?.toLowerCase() === "block" && (botSig === undefined || botSig.action?.toLowerCase() === "block")) policyMessages.add({ block: true, message: `Request ${msgJson.supportId} WOULD be blocked (${msgJson.clientClass}, ${msgJson.botSignatureName}).` })
    } else {

        const xmlParserOptions = {
            attributeNamePrefix: "@_",
            attrNodeName: "attr",
            textNodeName: "#text",
            ignoreAttributes: true,
            ignoreNameSpace: false,
            allowBooleanAttributes: false,
            parseNodeValue: true,
            parseAttributeValue: false,
            trimValues: true,
            cdataTagName: "__cdata",
            cdataPositionChar: "\\c",
            parseTrueNumberOnly: false,
            arrayMode: true,
            attrValueProcessor: (val, attrName) => he.decode(val, { isAttributeValue: true }),
            tagValueProcessor: (val, tagName) => he.decode(val),
            stopNodes: ["parse-me-as-string"]
        }

        let jsonObj
        try {
            if (XmlParser.validate(msgJson.violationDetails) === true) { //optional (it'll return an object in case it's not valid)
                jsonObj = XmlParser.parse(msgJson.violationDetails, xmlParserOptions)
                processRequestViolations(jsonObj.BAD_MSG[0]["request-violations"][0].violation, msgJson.supportId)
            }
        } catch (error) {
            console.error(`Error parsing Xml value: ${jsonObj.BAD_MSG}`)
        }
    }

    return exports.sendMessages()
}

const processRequestViolations = (requestViolations, supportId) => {
    let violationBlockStatus = false

    requestViolations.forEach(violation => {
        try {
            switch (violation.viol_name) {
                case "VIOL_ATTACK_SIGNATURE":
                    // for each sig_id, look up in the signatures file. would block = true if the accuracy is "high"
                    const lookupViolation = violation.sig_data.forEach(sigdata => {
                        const sigDetails = signatureDB.signatures.find(s => s.signatureId === sigdata.sig_id)
                        if (sigDetails !== undefined && sigDetails.accuracy.toLowerCase() === "high") {
                            violationBlockStatus = true
                            policyMessages.add({ block: true, message: `Request ${supportId} WOULD be blocked (high accuracy signature ${sigdata.sig_id}).` })
                            return
                        }
                    })
                    break
                case "VIOL_BOT_CLIENT":
                    // for some reason, this violation is not being logged. Hmmm....need to talk to the NAP team about this.
                    break
                default:
                    if (defaultPolicy.policy["blocking-settings"]["violations"].find(viol => viol.name === violation.viol_name) !== undefined) {
                        const lookupViolation = defaultPolicy.policy["blocking-settings"]["violations"].find(viol => viol.name === violation.viol_name)
                        if (lookupViolation.block) {
                            violationBlockStatus = true
                            policyMessages.add({ block: true, message: `Request ${supportId} WOULD be blocked (violation '${violation.viol_name}'set to 'block').` })
                            return
                        }
                    }
            }
        } catch (error) {
            console.error(`${error} violation: ${JSON.stringify(violation)}`)
        }
    })
    if (!violationBlockStatus) policyMessages.add({ block: false, message: `Request ${supportId} WOULD NOT be blocked.` })
}

exports.sendMessages = () => {
    return JSON.stringify({ messages: policyMessages }, MapSet_toJSON)
}

const b64Decode = (txt) => {
    return Buffer.from(txt, 'base64').toString('utf-8')
}

const MapSet_toJSON = (key, value) => {
    if (typeof value === 'object' && value instanceof Map) {
        return [...value.values()]
    } else if (typeof value === 'object' && value instanceof Set) {
        return [...value]
    } else {
        return value
    }
}
