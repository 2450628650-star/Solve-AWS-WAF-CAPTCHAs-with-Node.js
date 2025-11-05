
## 1. Abstract
AWS Web Application Firewall (WAF) is a critical security layer that often deploys Challenges (HTTP 202) or Managed Captchas (often HTTP 405) to protect web resources from automated threats. While these mechanisms are effective, they pose a significant barrier to legitimate automation tasks like web scraping, monitoring, and testing.

This article provides a practical, technical guide focused on using the specialized service CapSolver with Node.js to programmatically bypass AWS WAF protections. We will detail the WAF’s mechanism, demonstrate how to extract the necessary parameters using cheerio, and provide a complete, runnable Node.js script that leverages CapSolver’s AntiAwsWafTask to obtain the required aws-waf-token cookie. The emphasis is on a production-grade solution that is technically sound and immediately applicable.

## 2. Technical Analysis of the AWS WAF Challenge Mechanism
The core function of the AWS WAF challenge is to execute a client-side proof-of-work to verify the client is a legitimate browser.

### 2.1 Initial Request Interception
The WAF intercepts the request and returns a challenge page containing obfuscated JavaScript code and various encrypted parameters (awsKey, awsIv, awsContext, awsChallengeJS).

### 2.2 Status Code Logic

• HTTP 202 (Accepted): Indicates a WAF Challenge. The client must execute the JS to compute a payload and submit it to a WAF endpoint.

• HTTP 405 (Method Not Allowed): Often indicates a more complex WAF Captcha is required, which involves solving a visual puzzle in addition to the challenge logic.

### 2.3 Token Acquisition
The successful execution of the challenge or captcha results in a time-sensitive aws-waf-token cookie, which must be included in all subsequent requests to access the protected resource.

Our solution focuses on automating the extraction of these parameters and outsourcing the complex JS execution/Captcha solving to CapSolver.

## 3. Step-by-Step Implementation with Node.js
### 3.1 Prerequisites
Before you begin, ensure you have the following environment and information ready:

• Node.js Environment: Node.js is installed on your system (LTS version recommended).
• CapSolver API Key: You need a CapSolver account and your API key. Get your CapSolver API Key
• Proxy (Optional): If the target website has geo-restrictions or you need to hide your real IP, prepare an HTTP/HTTPS proxy.
### 3.2 Step One: Install Necessary Dependencies
In your project directory, execute the following command to install the required Node.js modules:

```
npm install axios cheerio
```
• axios: Used for sending HTTP requests.
• cheerio: Used for parsing HTML content and extracting parameters required for the AWS WAF challenge.

### 3.3 Step Two: Node.js Core Code Implementation
Below is the Node.js script for solving AWS WAF Challenges and Captchas. It automatically detects the status code returned by the website and executes the corresponding CapSolver task as needed.

Please save the following code as aws_waf_solver.js.

```
const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');

// ⚠️ Configuration: Please replace with your actual values
const CLIENT_KEY = "YOUR_CAPSOLVER_API_KEY"; // Replace with your CapSolver API Key
const PAGE_URL = "https://norway-meetup.aws.wslab.no/"; // Replace with the target website URL
const PROXY = "YOUR_PROXY_ADDRESS"; // Replace with your proxy address (Format: user:pass@ip:port or ip:port)

// --- Helper Functions ---

/**
 * Pauses execution for a specified number of milliseconds
 * @param {number} ms Milliseconds
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Creates a task with CapSolver
 * @param {object} payload Task payload
 * @returns {Promise<object>} Task creation result
 */
async function createTask(payload) {
    try {
        const res = await axios.post('https://api.capsolver.com/createTask', {
            clientKey: CLIENT_KEY,
            task: payload
        });
        if (res.data.errorId !== 0) {
            throw new Error(`CapSolver API Error: ${res.data.errorDescription}`);
        }
        return res.data;
    } catch (error) {
        console.error("Failed to create CapSolver task:", error.message);
        return null;
    }
}

/**
 * Gets the CapSolver task result until the task is completed
 * @param {string} taskId Task ID
 * @returns {Promise<object>} Task result
 */
async function getTaskResult(taskId) {
    if (!taskId) return null;
    console.log(`Waiting for task result (ID: ${taskId})...`);
    try {
        let success = false;
        let result = null;
        while (!success) {
            await sleep(3000); // Query every 3 seconds
            const res = await axios.post('https://api.capsolver.com/getTaskResult', {
                clientKey: CLIENT_KEY,
                taskId: taskId
            });

            if (res.data.errorId !== 0) {
                throw new Error(`CapSolver API Error: ${res.data.errorDescription}`);
            }

            if (res.data.status === "ready") {
                success = true;
                result = res.data;
                console.log("Task completed, solution obtained.");
            } else if (res.data.status === "processing") {
                console.log("Task is still processing...");
            }
        }
        return result;
    } catch (error) {
        console.error("Failed to get CapSolver task result:", error.message);
        return null;
    }
}

// --- Core Solver Functions ---

/**
 * Solves AWS WAF Challenge (Status Code 202)
 * @param {string} awsChallengeJS AWS Challenge JavaScript URL
 * @returns {Promise<string|null>} Solved AWS WAF Cookie value
 */
async function solveAwsChallenge(awsChallengeJS) {
    console.log("AWS WAF Challenge detected (Status Code 202), starting to solve...");
    const taskPayload = {
        type: "AntiAwsWafTask",
        websiteURL: PAGE_URL,
        awsChallengeJS,
        proxy: PROXY
    };
    const taskData = await createTask(taskPayload);
    if (!taskData) return null;

    const result = await getTaskResult(taskData.taskId);
    if (result && result.solution && result.solution.cookie) {
        return result.solution.cookie;
    }
    return null;
}

/**
 * Solves AWS WAF Captcha + Challenge (Status Code 405)
 * @param {string} htmlContent HTML content containing Captcha parameters
 * @param {string} awsChallengeJS AWS Challenge JavaScript URL
 * @returns {Promise<string|null>} Solved AWS WAF Cookie value
 */
async function solveAwsCaptchaChallenge(htmlContent, awsChallengeJS) {
    console.log("AWS WAF Captcha detected (Status Code 405), starting to solve...");
    const $ = cheerio.load(htmlContent);
    const scriptContent = $("script[type='text/javascript']").last().html();

    if (!scriptContent) {
        console.error("Could not find the script content containing Captcha parameters.");
        return null;
    }

    // Use regular expressions to extract key parameters
    const keyMatch = /"key":"(.*?)"/.exec(scriptContent);
    const ivMatch = /"iv":"(.*?)"/.exec(scriptContent);
    const contextMatch = /"context":"(.*?)"/.exec(scriptContent);

    const key = keyMatch ? keyMatch[1] : null;
    const iv = ivMatch ? ivMatch[1] : null;
    const context = contextMatch ? contextMatch[1] : null;

    if (!key || !iv || !context) {
        console.error("Failed to extract all required Captcha parameters (key, iv, context) from the script.");
        return null;
    }

    console.log(`Extracted Parameters: Key=${key}, IV=${iv}, Context=${context}`);

    const taskPayload = {
        type: "AntiAwsWafTask", // CapSolver uses this task type uniformly
        websiteURL: PAGE_URL,
        awsKey: key,
        awsIv: iv,
        awsContext: context,
        awsChallengeJS,
        proxy: PROXY
    };

    const taskData = await createTask(taskPayload);
    if (!taskData) return null;

    const result = await getTaskResult(taskData.taskId);
    if (result && result.solution && result.solution.cookie) {
        return result.solution.cookie;
    }
    return null;
}

/**
 * Main execution function
 */
async function main() {
    let awsWafCookie = null;
    let initialResponse = null;

    // 1. Initial request to the target page
    try {
        console.log(`Requesting target page: ${PAGE_URL}`);
        initialResponse = await axios.get(PAGE_URL, {
            headers: {
                // Simulate browser request headers
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "max-age=0",
                "Upgrade-Insecure-Requests": "1"
            },
            // Allow processing 2xx, 3xx, 4xx status codes
            validateStatus: (status) => status >= 200 && status < 500
        });
        console.log(`Initial response status code: ${initialResponse.status}`);
    } catch (error) {
        console.error(`Initial request failed: ${error.message}`);
        return;
    }

    const $ = cheerio.load(initialResponse.data);
    const scriptTags = $('script[src*="token.awswaf.com"]');
    const awsChallengeJS = scriptTags.attr('src');

    if (!awsChallengeJS) {
        console.log("AWS WAF challenge script not detected. The website may not be protected or has already passed.");
        // If no challenge script, use the initial response directly
        if (initialResponse.status === 200) {
            console.log("Website loaded successfully.");
            // console.log(initialResponse.data); // Print final content
            return;
        }
    } else {
        console.log(`AWS WAF challenge script URL detected: ${awsChallengeJS}`);
    }


    // 2. Determine and solve the challenge/captcha based on the status code
    if (initialResponse.status === 202) {
        // AWS WAF Challenge only
        awsWafCookie = await solveAwsChallenge(awsChallengeJS);
    } else if (initialResponse.status === 405) {
        // AWS WAF Captcha + Challenge
        awsWafCookie = await solveAwsCaptchaChallenge(initialResponse.data, awsChallengeJS);
    } else if (initialResponse.status === 200) {
        console.log("Website loaded successfully, no captcha solving required.");
        // console.log(initialResponse.data); // Print final content
        return;
    } else {
        console.log(`Encountered unhandled status code: ${initialResponse.status}.`);
        return;
    }

    // 3. Request the target page again using the obtained Cookie
    if (awsWafCookie) {
        try {
            console.log("\n--- Second Request: Using AWS WAF Cookie ---");
            console.log(`Cookie used: ${awsWafCookie}`);

            const finalResponse = await axios.get(PAGE_URL, {
                headers: {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
                    "Cookie": `aws-waf-token=${awsWafCookie}`
                },
                validateStatus: (status) => status === 200 // Expect final success
            });

            console.log(`Final response status code: ${finalResponse.status}`);
            console.log("Website content retrieved successfully!");
            // console.log(finalResponse.data); // Print final content
        } catch (error) {
            console.error(`Final request failed: ${error.message}`);
        }
    } else {
        console.log("Failed to obtain AWS WAF Cookie, unable to perform the second request.");
    }
}

main();
```

### 3.4 Key Points Summary

 <img width="694" height="710" alt="image" src="https://github.com/user-attachments/assets/6ac907dc-a6a1-4167-aa9c-969c52c9f692" />


## 4. Conclusion
This guide has demonstrated a robust and efficient method for programmatically solving AWS WAF Challenges and Captchas using Node.js and CapSolver. By implementing the modular script and leveraging CapSolver’s specialized task type, you can seamlessly integrate this solution into your automation workflows. The key to success lies in correctly identifying the WAF status code (202 or 405), extracting the necessary parameters, and using the resulting aws-waf-token cookie for subsequent requests. This approach ensures your automation tasks can reliably access content protected by AWS WAF.
