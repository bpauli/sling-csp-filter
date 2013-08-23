//$URL: $
//$Id: $
package de.bpauli.sling.csp;

import org.apache.felix.scr.annotations.sling.SlingServlet;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import java.io.IOException;
import java.io.PrintWriter;

@SlingServlet(
        resourceTypes="sling/servlet/default",
        methods = "POST",
        selectors = CSPReportServlet.SERVLET_SELECTOR
)
public class CSPReportServlet extends SlingAllMethodsServlet {

    Logger logger = LoggerFactory.getLogger(CSPReportServlet.class);

    public static final String SERVLET_SELECTOR = "csp_violation";

    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response) throws ServletException, IOException {
        logger.info("POST of violation");
        PrintWriter writer = response.getWriter();
        writer.append("POST of violation");
    }
}
