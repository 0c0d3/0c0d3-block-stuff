// Function to check if a request is third-party
function isThirdPartyRequest(details) {
    // Validate initiator or referrer before creating URL
    const parentUrl = details.initiator ? new URL(details.initiator) : null;
    const referrerUrl = details.referrer ? new URL(details.referrer) : null;
    const currentUrl = new URL(details.url);

    // Check if either the initiator or referrer is different from the current URL's hostname
    return (parentUrl && currentUrl.hostname !== parentUrl.hostname) || 
           (referrerUrl && currentUrl.hostname !== referrerUrl.hostname);
}

// Block specific resource types and headers for enhanced privacy
chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        const blockedTypes = ["stylesheet", "font", "image", "sub_frame", "object", "script"];

        // Block resources if they match the blocked types or are third-party
        if (blockedTypes.includes(details.type) || isThirdPartyRequest(details)) {
            console.log("Blocked resource:", details.url);
            return { cancel: true }; // Block these resource types
        }

        return {}; // Allow all other resources
    },
    { urls: ["<all_urls>"] }, // Apply to all URLs
    ["blocking"]
);

// Block outgoing cookies by removing the Cookie header
chrome.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        console.log("Blocked outgoing cookies for:", details.url);
        
        for (let i = 0; i < details.requestHeaders.length; ++i) {
            if (details.requestHeaders[i].name.toLowerCase() === "cookie") {
                details.requestHeaders.splice(i, 1); // Remove the cookie header
                break;
            }
        }
        
        return { requestHeaders: details.requestHeaders };
    },
    { urls: ["<all_urls>"] }, // Apply to all URLs
    ["blocking", "requestHeaders"]
);

// Block incoming cookies by removing the Set-Cookie header
chrome.webRequest.onHeadersReceived.addListener(
    function(details) {
        console.log("Blocked incoming cookies for:", details.url);
        
        for (let i = 0; i < details.responseHeaders.length; ++i) {
            if (details.responseHeaders[i].name.toLowerCase() === "set-cookie") {
                details.responseHeaders.splice(i, 1); // Remove the Set-Cookie header
                break;
            }
        }
        
        return { responseHeaders: details.responseHeaders };
    },
    { urls: ["<all_urls>"] }, // Apply to all URLs
    ["blocking", "responseHeaders"]
);

// Block fingerprinting headers such as User-Agent and geolocation
chrome.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        console.log("Blocking fingerprinting headers for:", details.url);

        const headersToBlock = [
            "user-agent",          // Block User-Agent header
            "accept-language",     // Block Accept-Language header
            "referer",             // Block Referer header
            "accept-encoding",     // Block Accept-Encoding header
            "geolocation"          // Block geolocation headers
        ];

        details.requestHeaders = details.requestHeaders.filter(header => 
            !headersToBlock.includes(header.name.toLowerCase())
        );
        
        return { requestHeaders: details.requestHeaders };
    },
    { urls: ["<all_urls>"] }, // Apply to all URLs
    ["blocking", "requestHeaders"]
);

// Block access to specific fingerprinting APIs
chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        const fingerprintingAPIs = [
            "navigator.permissions",
            "navigator.geolocation.getCurrentPosition",
            "window.crypto.getRandomValues",
            "navigator.userAgent",
            "navigator.plugins",
            "navigator.languages",
            "window.localStorage",
            "window.sessionStorage"
        ];

        // Check if the request URL contains any of the fingerprinting APIs
        if (fingerprintingAPIs.some(api => details.url.includes(api))) {
            console.log("Blocked fingerprinting API access:", details.url);
            return { cancel: true }; // Block the request
        }

        return {};
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
);

// Block CSS requests
chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        if (details.type === "stylesheet") {
            console.log("Blocked CSS request:", details.url);
            return { cancel: true }; // Block all CSS requests
        }
        return {};
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
);

// Block access to specific headers that can reveal browser and OS information
chrome.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        const browserOSHeadersToBlock = [
            "user-agent",          // Block User-Agent
            "sec-ch-ua",          // Block Client Hints
            "sec-ch-ua-mobile",   // Block mobile Client Hints
            "sec-ch-ua-platform"  // Block platform Client Hints
        ];

        console.log("Blocking headers that reveal browser and OS information for:", details.url);
        details.requestHeaders = details.requestHeaders.filter(header => 
            !browserOSHeadersToBlock.includes(header.name.toLowerCase())
        );

        return { requestHeaders: details.requestHeaders };
    },
    { urls: ["<all_urls>"] },
    ["blocking", "requestHeaders"]
);
