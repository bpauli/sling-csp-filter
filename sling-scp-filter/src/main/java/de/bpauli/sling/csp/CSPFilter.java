package de.bpauli.sling.csp;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.sling.SlingFilter;
import org.apache.felix.scr.annotations.sling.SlingFilterScope;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.request.RequestPathInfo;
import org.apache.sling.api.wrappers.SlingRequestPaths;

import javax.servlet.*;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Content Security Policy filter
 */
@SlingFilter(
        scope = SlingFilterScope.REQUEST,
        order = Integer.MIN_VALUE
)
@SuppressWarnings("unused")
public class CSPFilter implements Filter {

    /**
     * Used for Script Nonce
     */
    private SecureRandom prng = null;

    /**
     * Set for the csp headers;
     */
    private List<String> cspHeaders = new ArrayList<String>();

    /**
     * Collection of policies that will be applied
     */
    String policies = null;

    @Reference
    CSPConfigProvider config;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Init secure random
        try {
            this.prng = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new ServletException(e);
        }

        cspHeaders.add("Content-Security-Policy" + (config.isReportOnly() ? "-Report-Only" : ""));
        cspHeaders.add("X-Content-Security-Policy" + (config.isReportOnly() ? "-Report-Only" : ""));
        cspHeaders.add("X-WebKit-CSP" + (config.isReportOnly() ? "-Report-Only" : ""));
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!config.isEnabled() ||
                !(response instanceof SlingHttpServletResponse) ||
                !(request instanceof SlingHttpServletRequest) ||
                request.getAttribute(SlingRequestPaths.INCLUDE_REQUEST_URI) != null) {
            chain.doFilter(request, response);
            return;
        }

        SlingHttpServletResponse slingResponse = (SlingHttpServletResponse) response;
        SlingHttpServletRequest slingRequest = (SlingHttpServletRequest) request;
        RequestPathInfo requestPathInfo = slingRequest.getRequestPathInfo();

        List<String> cspPolicies = new ArrayList<String>();
        cspPolicies.add("connect-src " + config.getConnectSrc().toString().replaceAll(",", "").trim());
        cspPolicies.add("default-src " + config.getDefaultSrc().toString().replaceAll(",", "").trim());
        cspPolicies.add("script-src " + config.getScriptSrc().toString().replaceAll(",", "").trim());
        cspPolicies.add("style-src " + config.getStyleSrc().toString().replaceAll(",", "").trim());
        cspPolicies.add("img-src " + config.getImgSrc().toString().replaceAll(",", "").trim());
        if(config.isReportEnabled() || config.isReportOnly()) {
            cspPolicies.add("report-uri " + requestPathInfo.getResourcePath()  + "."
                    + CSPReportServlet.SERVLET_SELECTOR + "."  + requestPathInfo.getExtension());
        }

        StringBuilder policiesBuffer = new StringBuilder(cspPolicies.toString().replaceAll("(\\[|\\])", "")
                .replaceAll(",", ";").trim());
        if(isFrame(requestPathInfo)) {
            policiesBuffer.append(";").append("frame-src 'self';sandbox");
            if(config.isMozillaDirectives()) {
                policiesBuffer.append(";").append("frame-ancestors 'self'");
            }
        }

        for (String requestPath : config.getRequestPaths()) {
            if (requestPathInfo.getResourcePath().startsWith(requestPath)) {
                for (String header : cspHeaders) {
                    slingResponse.addHeader(header, policiesBuffer.toString());
                }
            }
        }

        // set script nonce in request attribute
        slingRequest.setAttribute("CSP_SCRIPT_NONCE", getNonce());

        chain.doFilter(request, slingResponse);

    }

    private String getNonce() throws ServletException {
        // Add Script Nonce CSP Policy
        // --Generate a random number
        String randomNum = Integer.toString(this.prng.nextInt());
        // --Get its digest
        MessageDigest sha;
        try {
            sha = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new ServletException(e);
        }
        byte[] digest = sha.digest(randomNum.getBytes());
        // --Encode it into HEXA
        return Hex.encodeHexString(digest);
    }

    private boolean isFrame(RequestPathInfo requestPathInfo) {
        String frameSelector = config.getFrameSelctor();
        String[] selectors = requestPathInfo.getSelectors();
        if (StringUtils.isBlank(frameSelector) || selectors.length == 0) {
            return false;
        }

        for (String selector : selectors) {
            if (selector.equals(frameSelector)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public void destroy() {
        // nothing to do
    }
}
