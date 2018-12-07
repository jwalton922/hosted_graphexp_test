SigV4Utils= {};
SigV4Utils.getSignatureKey = function (key, date, region, service) {
    var kDate = AWS.util.crypto.hmac('AWS4' + key, date, 'buffer');
    var kRegion = AWS.util.crypto.hmac(kDate, region, 'buffer');
    var kService = AWS.util.crypto.hmac(kRegion, service, 'buffer');
    var kCredentials = AWS.util.crypto.hmac(kService, 'aws4_request', 'buffer');    
    return kCredentials;
};

SigV4Utils.getSignedUrl = function(host, region, credentials, protocol, method) {
    var datetime = AWS.util.date.iso8601(new Date()).replace(/[:\-]|\.\d{3}/g, '');
    var date = datetime.substr(0, 8);
    
    
    var protocol = protocol;
    var uri = '/gremlin/';
    var service = 'neptune-db';
    var algorithm = 'AWS4-HMAC-SHA256';

    var credentialScope = date + '/' + region + '/' + service + '/' + 'aws4_request';
    var canonicalQuerystring = 'X-Amz-Algorithm=' + algorithm;
    canonicalQuerystring += '&X-Amz-Credential=' + encodeURIComponent(credentials.accessKeyId + '/' + credentialScope);
    canonicalQuerystring += '&X-Amz-Date=' + datetime;
    canonicalQuerystring += '&X-Amz-SignedHeaders=host;x-amz-date';

    var canonicalHeaders = 'host:' + host + '\n'+ 'x-amz-date:' + datetime + '\n';
    var payloadHash = AWS.util.crypto.sha256('', 'hex')
    var canonicalRequest = method + '\n' + uri + '\n' + canonicalQuerystring + '\n' + canonicalHeaders + '\nhost\n' + payloadHash;

    var stringToSign = algorithm + '\n' + datetime + '\n' + credentialScope + '\n' + AWS.util.crypto.sha256(canonicalRequest, 'hex');
    var signingKey = SigV4Utils.getSignatureKey(credentials.secretAccessKey, date, region, service);
    var signature = AWS.util.crypto.hmac(signingKey, stringToSign, 'hex');

    canonicalQuerystring += '&X-Amz-Signature=' + signature;
    if (credentials.sessionToken) {
        canonicalQuerystring += '&X-Amz-Security-Token=' + encodeURIComponent(credentials.sessionToken);
    }

    var requestUrl = protocol + '//' + host + uri + '?' + canonicalQuerystring;
    return requestUrl;
};

SigV4Utils.joshSignedUrl = function(host, method, query_type, query,protocol, credentials,region){
    var service = 'neptune-db'
    var endpoint = protocol + '//' + host
    
    console.log('+++++ USER INPUT +++++')
    console.log('host = ' + host)
    console.log('method = ' + method)
    console.log('query_type = ' + query_type)
    console.log('query = ' + query)

    //# validate input
    // validate_input(method, query_type)

    //# get canonical_uri and payload
    var canonical_uri= '/gremlin/';//get_canonical_uri_and_payload(query_type, query)
    //maybe only do this for HTTP and not for WS ???
    var payload = '';
    if(method.startsWith('http')){
      payload = {gremlin: query};
    }
    //# ************* REQUEST VALUES *************

    //# do the encoding => quote_via=urllib.parse.quote is used to map " " => "%20"
    var request_parameters = encodeURIComponent(JSON.stringify(payload));//urllib.parse.urlencode(payload, quote_via=urllib.parse.quote));
    console.log("Request parameters: ",request_parameters);
    //# ************* TASK 1: CREATE A CANONICAL REQUEST *************
    //# http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    //# Step 1 is to define the verb (GET, POST, etc.)--already done.

    //# Create a date for headers and the credential string.
    // amzdate = t.strftime('%Y%m%dT%H%M%SZ')
    // datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope
    var amzdate = AWS.util.date.iso8601(new Date()).replace(/[:\-]|\.\d{3}/g, '');
    var datestamp = amzdate.substr(0, 8);
    
   
    //# ************* TASK 1: CREATE A CANONICAL REQUEST *************
    //# http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    //# Step 1 is to define the verb (GET, POST, etc.)--already done.
    //# Step 2: is to define the canonical_uri--already done.

    //# Step 3: Create the canonical query string. In this example (a GET request),
    //# request parameters are in the query string. Query string values must
    //# be URL-encoded (space=%20). The parameters must be sorted by name.
    //# For this example, the query string is pre-formatted in the request_parameters variable.
    var canonical_querystring = '';
    if (method === 'GET'){
        canonical_querystring = request_parameters;
    } else if (method === 'POST'){
        canonical_querystring = '';
    }
    else{
        console.log('Request method is neither "GET" nor "POST", something is wrong here.');        
    }
    //# Step 4: Create the canonical headers and signed headers. Header names
    //# must be trimmed and lowercase, and sorted in code point order from
    //# low to high. Note that there is a trailing \n.
    var canonical_headers = 'host:' + host + '\n'+ 'x-amz-date:' + amzdate + '\n';

    //# Step 5: Create the list of signed headers. This lists the headers
    //# in the canonical_headers list, delimited with ";" and in alpha order.
    //# Note: The request can include any headers; canonical_headers and
    //# signed_headers lists those that you want to be included in the
    //# hash of the request. "Host" and "x-amz-date" are always required.
    var signed_headers = 'host;x-amz-date';

    //# Step 6: Create payload hash (hash of the request body content). For GET
    //# requests, the payload is an empty string ("").
    if (method == 'GET'){
        post_payload = '';
    } else if (method == 'POST'){ 
        post_payload = request_parameters;
    } else {
        console.log('Request method is neither "GET" nor "POST", something is wrong here.');
    }                

    var payload_hash = AWS.util.crypto.sha256(post_payload, 'hex');

    //# Step 7: Combine elements to create canonical request.
    var canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash;

    //# ************* TASK 2: CREATE THE STRING TO SIGN*************
    //# Match the algorithm to the hashing algorithm you use, either SHA-1 or
    //# SHA-256 (recommended)
    var algorithm = 'AWS4-HMAC-SHA256'
    var credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
    var string_to_sign = algorithm + '\n' + amzdate + '\n' + credential_scope + '\n' + AWS.util.crypto.sha256(canonical_request);

    //# ************* TASK 3: CALCULATE THE SIGNATURE *************
    //# Create the signing key using the function defined above.
    var signing_key = this.getSignatureKey(credentials.secretAccessKey, datestamp, region, service);

    //# Sign the string_to_sign using the signing_key
    var signature = AWS.util.crypto.hmac(signing_key, string_to_sign, 'hex');

    //# ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    //# The signing information can be either in a query string value or in
    //# a header named Authorization. This code shows how to use a header.
    //# Create authorization header and add to request headers
    var authorization_header = algorithm + ' ' 
    + 'Credential=' + credentials.accessKeyId + '/' + credential_scope + ', ' 
    + 'SignedHeaders=' + signed_headers + ', ' 
    + 'Signature=' + signature;

    //# The request can include any headers, but MUST include "host", "x-amz-date",
    //# and (for this scenario) "Authorization". "host" and "x-amz-date" must
    //# be included in the canonical_headers and signed_headers, as noted
    //# earlier. Order here is not significant.
    //# Python note: The 'host' header is added automatically by the Python 'requests' library.
    var headers = '';
    if (method == 'GET'){
        headers = {'x-amz-date': amzdate, 'Authorization': authorization_header};
    } else if (method == 'POST'){
        headers = {'content-type': 'application/x-www-form-urlencoded', 'x-amz-date': amzdate,
                   'Authorization': authorization_header};
    } else {
        console.log('Request method is neither "GET" nor "POST", something is wrong here.');
    }
    console.log("Headers",headers);
    var canonicalQuerystring = 'X-Amz-Algorithm=' + algorithm;
    canonicalQuerystring += '&X-Amz-Credential=' + encodeURIComponent(credentials.accessKeyId + '/' + credential_scope);
    canonicalQuerystring += '&X-Amz-Date=' + amzdate;
    canonicalQuerystring += '&X-Amz-SignedHeaders=connection;host;upgrade;x-amz-date;';
    canonicalQuerystring += '&X-Amz-Signature=' + signature;
    if (credentials.sessionToken) {
        canonicalQuerystring += '&X-Amz-Security-Token=' + encodeURIComponent(credentials.sessionToken);
    }
        
    // var retValues = {
    //     'X-Amz-Algorithm': algorithm,
    //     'X-Amz-Credential': cre
    // }    

    //# https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    //# The process for temporary security credentials is the same as using long-term credentials and
    //# for temporary security credentials should be added as parameter name is X-Amz-Security-Token.
    if (credentials.sessionToken){
        headers['x-amz-security-token'] = credentials.sessionToken;        
    }
    //# ************* SEND THE REQUEST *************
    var request_url = endpoint + canonical_uri;
    if(protocol.startsWith("ws")){
        request_url = request_url+'?'+canonicalQuerystring;
    }
    console.log("url: "+request_url);
    return {url: request_url, headers: headers};
};
