const https = require('https');
const { get } = require("request")

// moduel to get there IP address and locations

const options = {
    host: "realwbx.com",
    path: "/ip?f=json",
    method: "GET",
    headers: {
        "User-Agent": "Mozilla/5.0 NodeJs v3.3.2",
        "Authorization": "Bearer xHlT6gllTfGbKgdivAKTzWKxrILWlNlv"
    }
}

// Function to Get your IP Address
function getIPAddress() {
    return new Promise((resolve, reject) => {
        https.get(options, (res) => {
            let data = "";

            res.on("data", (chunk) => {
                data += chunk;
            })

            res.on("end", () => {
                try {
                    const trimmed = data.trim();
                    const parsed = trimmed.startsWith("{") ? JSON.parse(trimmed) : trimmed;
                    resolve(parsed);
                } catch (error) {
                    reject(error);
                }
            })
        })
    })
}

getIPAddress();

module.exports = { getIPAddress };