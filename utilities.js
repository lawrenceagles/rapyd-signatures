const https = require('https');
const crypto = require('crypto');
const axios = require('axios').default;

const accessKey = "BFB4657FE016ADAFFE51";
const secretKey = "14cf72f1ab2b8316e1f6bfa2dbc1d87bb6ffc67e0d300922bf7b824c64546d13b2ca31816353edb5";
const log = false;

async function makeRequest(method, urlPath, body = null) {

    try {
        httpMethod = method;
        httpBaseURL = "https://sandboxapi.rapyd.net";
        httpURLPath = urlPath;
        salt = generateRandomString(8);
        idempotency = new Date().getTime().toString();
        timestamp = Math.round(new Date().getTime() / 1000);
        signature = sign(httpMethod, httpURLPath, salt, timestamp, body)

        const options = {
            hostname: httpBaseURL,
            port: 443,
            path: httpURLPath,
            method: httpMethod,
            headers: {
                'Content-Type': 'application/json',
                salt: salt,
                timestamp: timestamp,
                signature: signature,
                access_key: accessKey,
                idempotency: idempotency
            }
        }

        return await httpRequestAxios(options);

        return options
    }
    catch (error) {
        console.error("Error generating request options");
        throw error;
    }
}

function sign(method, urlPath, salt, timestamp, body) {

    try {
        let bodyString = "";
        if (body) {
            bodyString = JSON.stringify(body);
            bodyString = bodyString == "{}" ? "" : bodyString;
        }

        let toSign = method.toLowerCase() + urlPath + salt + timestamp + accessKey + secretKey + bodyString;
        log && console.log(`toSign: ${toSign}`);

        let hash = crypto.createHmac('sha256', secretKey);
        hash.update(toSign);
        const signature = Buffer.from(hash.digest("hex")).toString("base64")
        log && console.log(`signature: ${signature}`);

        return signature;
    }
    catch (error) {
        console.error("Error generating signature");
        throw error;
    }
}

function generateRandomString(size) {
    try {
        return crypto.randomBytes(size).toString('hex');
    }
    catch (error) {
        console.error("Error generating salt");
        throw error;
    }
}

async function httpRequestAxios({ httpMethod, hostname, path, headers }) {
    try {
        const response = await axios({
            method: httpMethod,
            baseURL: hostname,
            url: path,
            headers
        });

        return response.data;

    } catch (error) {
        console.error(error.message);
        return error;
    }
}

exports.makeRequest = makeRequest;