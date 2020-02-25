/*
 * Session Management script for OWASP Juice Shop
 *
 * For Authentication select:
 * Authentication method: JSON-based authentication
 * Login FORM target URL: http://localhost:3000/rest/user/login
 * URL to GET Login Page: http://localhost:3000/
 * Login Request POST data: {"email":"test@test.com","password":"test1"}
 * Username Parameter: email
 * Password Parameter: password
 * Logged out regex: \Q{"user":{}}\E
 *
 * Obviously update with any local changes as necessary.
 */

var COOKIE_TYPE   = org.parosproxy.paros.network.HtmlParameter.Type.cookie;
var HtmlParameter = Java.type('org.parosproxy.paros.network.HtmlParameter')

function extractWebSession(sessionWrapper) {
        print('@@extractWebSession:1');
        // parse the authentication response
        print('@@extractWebSession:2:: ' + sessionWrapper.getHttpMessage().getResponseBody().toString());
        var json = JSON.parse(sessionWrapper.getHttpMessage().getResponseBody().toString());
        print('@@extractWebSession:3:: ' + json);
        var token = json.Authorization;
        var jsessionid = json.JSESSIONID;
        print('>>> jsessionid: ' + jsessionid);
        // save the authentication token
        sessionWrapper.getSession().setValue("EBX_Authorization", token);
        sessionWrapper.getSession().setValue("JSESSIONID", jsessionid);
}
   
function clearWebSessionIdentifiers(sessionWrapper) {
        print('@@clearWebSessionIdentifiers:1');
        var headers = sessionWrapper.getHttpMessage().getRequestHeader();
        print('>>> headers: ');
        headers.setHeader("Authorization", null);
        headers.setHeader("JSESSIONID", null);
}
   
function processMessageToMatchSession(sessionWrapper) {
        print('@@processMessageToMatchSession:1');
        print('>>> processMessageToMatchSession: 1');
        var token = sessionWrapper.getSession().getValue("EBX_Authorization");
        var jsessionid = sessionWrapper.getSession().getValue("JSESSIONID");
        print('>>> processMessageToMatchSession: 2');
        if (token === null) {
            print('EBX mgmt script: no token');
            return;
        }
        print('>>> processMessageToMatchSession: 3');
        var cookie = new HtmlParameter(COOKIE_TYPE, "Authorization", token);
        var cookiejsessionid = new HtmlParameter(COOKIE_TYPE, "JSESSIONID", jsessionid);
       
        // add the saved authentication token as an Authentication header and a cookie
        var msg = sessionWrapper.getHttpMessage();
        msg.getRequestHeader().setHeader("Authorization", token);
        var cookies = msg.getRequestHeader().getCookieParams();
        cookies.add(cookie);
                cookies.add(cookiejsessionid);
        msg.getRequestHeader().setCookieParams(cookies);
}

function getRequiredParamsNames() {
        print('>>> getRequiredParamsNames: 1');
        return ["login", "password"];
}

function getOptionalParamsNames() {
        print('>>> getOptionalParamsNames: 1');
        return [];
}