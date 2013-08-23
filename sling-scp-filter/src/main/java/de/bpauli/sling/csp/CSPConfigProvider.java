package de.bpauli.sling.csp;

import org.apache.felix.scr.annotations.*;
import org.apache.sling.commons.osgi.PropertiesUtil;
import org.osgi.service.component.ComponentContext;

import java.util.*;

@Component(metatype = true, immediate = true,
        label = "Sling Content Security Policy Filter",
        description = "Configuration parameters for the csp service")
@Service(CSPConfigProvider.class)
public class CSPConfigProvider {

    @Property(
            label = "Enabled",
            description = "Content Security Policy filter is enabled.",
            boolValue = CSPConfigProvider.DEFAULT_PROPERTY_ENABLED)
    private static final String PROPERTY_ENABLED = "enabled";
    private static final boolean DEFAULT_PROPERTY_ENABLED = true;

    @Property(
            label = "Report Service enabled",
            description = "Send csp violation to log service",
            boolValue = CSPConfigProvider.DEFAULT_PROPERTY_REPORT_ENABLED)
    private static final String PROPERTY_REPORT_ENABLED = "report.enabled";
    private static final boolean DEFAULT_PROPERTY_REPORT_ENABLED = true;

    @Property(
            label = "Only Report",
            description = "Do only monitor csp violation and don't enforce policies",
            boolValue = CSPConfigProvider.DEFAULT_PROPERTY_REPORT_ONLY)
    private static final String PROPERTY_REPORT_ONLY = "report.only";
    private static final boolean DEFAULT_PROPERTY_REPORT_ONLY = false;

    @Property(
            label = "Enable Mozilla Directives",
            description = "Include specific mozilla related directives",
            boolValue = CSPConfigProvider.DEFAULT_PROPERTY_INCLUDE_MOZILLA_DIRECIVES)
    private static final String PROPERTY_INCLUDE_MOZILLA_DIRECIVES = "directives.mozilla";
    private static final boolean DEFAULT_PROPERTY_INCLUDE_MOZILLA_DIRECIVES = true;

    @Property(
            label = "Request Path",
            description = "List of paths for which the CSP filter is active",
            cardinality = 1000,
            value = {"/content"})
    private static final String PROPERTY_REQUEST_PATH = "request.path";
    private static final String[] DEFAULT_PROPERTY_REQUEST_PATH = {"/content"};

    @Property(
            label = "connect-src",
            description = "The connect-src directive restricts which URIs the protected resource can load using script interfaces.",
            cardinality = 1000,
            value = {"'self'"}
    )
    private static final String PROPERTY_CONNECT_SRC = "directive.connect";
    private static final String[] DEFAULT_PROPERTY_CONNECT_SRC = {"'self'"};

    @Property(
            label = "default-src",
            description = "Default Source Directive: Use one of the keywords 'none', 'self' and/or host information",
            cardinality = 1000,
            value = {"'none'"}
    )
    private static final String PROPERTY_DEFAULT_SRC = "directive.default";
    private static final String[] DEFAULT_PROPERTY_DEFAULT_SRC = {"'none'"};

    @Property(
            label = "script-src",
            description = "The script-src directive restricts which scripts the protected resource can execute",
            cardinality = 1000,
            value = {"'self', 'unsafe-eval'"}
    )
    private static final String PROPERTY_SCRIPT_SRC = "directive.script";
    private static final String[] DEFAULT_PROPERTY_SCRIPT_SRC = {"'self', 'unsafe-eval'"};

    private static final String[] DEFAULT_PROPERTY_IMG_SRC = {"*"};
    @Property(
            label = "img-src",
            description = "The img-src directive restricts from where the protected resource can load images.",
            cardinality = 1000,
            value = {"*"}
    )
    private static final String PROPERTY_IMG_SRC = "directive.img";


    @Property(
            label = "style-src",
            description = "The style-src directive restricts which styles the user applies to the protected resource. " +
                    "",
            cardinality = 1000,
            value = {"'self'", "'unsafe-inline'"}
    )
    private static final String PROPERTY_STYLE_SRC = "directive.style";
    private static final String[] DEFAULT_PROPERTY_STYLE_SRC = {"'self'"};


    private static final String DEFAULT_PROPTERY_FRAME_SELECTOR = "frame";
    @Property(
            label = "Selector used by frames",
            description = "To apply sandbox directive define a selector for frame detection",
            value = DEFAULT_PROPTERY_FRAME_SELECTOR
    )
    private static final String PROPTERY_FRAME_SELECTOR = "selector.frame";


    private boolean enabled;
    private boolean reportEnabled;
    private boolean reportOnly;
    private Set<String> requestPaths;
    private List<String> connectSrc;
    private List<String> defaultSrc;
    private List<String> styleSrc;
    private List<String> imgSrc;
    private List<String> scriptSrc;
    private String frameSelctor;
    private boolean mozillaDirectives;

    @Activate
    protected void activate(ComponentContext context) {
        @SuppressWarnings("unchecked")
        final Dictionary<String, Object> props = context.getProperties();

        enabled = PropertiesUtil.toBoolean(props.get(PROPERTY_ENABLED), DEFAULT_PROPERTY_ENABLED);

        reportEnabled = PropertiesUtil.toBoolean(props.get(PROPERTY_REPORT_ENABLED), DEFAULT_PROPERTY_REPORT_ENABLED);

        reportOnly = PropertiesUtil.toBoolean(props.get(PROPERTY_REPORT_ONLY), DEFAULT_PROPERTY_REPORT_ONLY);

        frameSelctor = PropertiesUtil.toString(props.get(PROPTERY_FRAME_SELECTOR), DEFAULT_PROPTERY_FRAME_SELECTOR);

        String[] requestPathsArray = PropertiesUtil.toStringArray(props.get(PROPERTY_REQUEST_PATH),
                DEFAULT_PROPERTY_REQUEST_PATH);
        requestPaths = new HashSet<String>();
        Collections.addAll(requestPaths, requestPathsArray);

        String[] connectSrcArray = PropertiesUtil.toStringArray(props.get(PROPERTY_CONNECT_SRC),
                DEFAULT_PROPERTY_CONNECT_SRC);
        connectSrc = new ArrayList<String>();
        Collections.addAll(connectSrc, connectSrcArray);

        String[] defaultSrcArray = PropertiesUtil.toStringArray(props.get(PROPERTY_DEFAULT_SRC),
                DEFAULT_PROPERTY_DEFAULT_SRC);
        defaultSrc = new ArrayList<String>();
        Collections.addAll(defaultSrc, defaultSrcArray);

        String[] styleSrcArray = PropertiesUtil.toStringArray(props.get(PROPERTY_STYLE_SRC),
                DEFAULT_PROPERTY_STYLE_SRC);
        styleSrc = new ArrayList<String>();
        Collections.addAll(styleSrc, styleSrcArray);

        String[] scriptSrcArray = PropertiesUtil.toStringArray(props.get(PROPERTY_SCRIPT_SRC),
                DEFAULT_PROPERTY_SCRIPT_SRC);
        scriptSrc = new ArrayList<String>();
        Collections.addAll(scriptSrc, scriptSrcArray);

        String[] imgSrcArray = PropertiesUtil.toStringArray(props.get(PROPERTY_IMG_SRC),
                DEFAULT_PROPERTY_IMG_SRC);
        imgSrc = new ArrayList<String>();
        Collections.addAll(imgSrc, imgSrcArray);

        mozillaDirectives = PropertiesUtil.toBoolean(props.get(PROPERTY_INCLUDE_MOZILLA_DIRECIVES),
                DEFAULT_PROPERTY_INCLUDE_MOZILLA_DIRECIVES);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isReportEnabled() {
        return reportEnabled;
    }

    public boolean isReportOnly() {
        return reportOnly;
    }

    public Set<String> getRequestPaths() {
        return requestPaths;
    }

    public String getFrameSelctor() {
        return frameSelctor;
    }

    public List<String> getConnectSrc() {
        return connectSrc;
    }

    public List<String> getDefaultSrc() {
        return defaultSrc;
    }

    public List<String> getStyleSrc() {
        return styleSrc;
    }

    public boolean isMozillaDirectives() {
        return mozillaDirectives;
    }

    public List<String> getImgSrc() {
        return imgSrc;
    }

    public List<String> getScriptSrc() {
        return scriptSrc;
    }
}
