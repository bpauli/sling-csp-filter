package de.bpauli.sling.csp;

public enum KeywordSource {
    NONE("none"),
    UNSAFE_EVAL("unsafe-eval"),
    UNSAFE_INLINE("unsafe-inline"),
    SELF("self");

    private String keyword;

    private KeywordSource(String keyword) {
        this.keyword = keyword;
    }

    public String getKeyword() {
        return keyword;
    }
}
