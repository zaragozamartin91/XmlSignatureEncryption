package com.ast.orchestration.util;


import java.util.Map;

public class XMLTransformer {

	private static final String PARAM_IDENTIFY, OPEN_SCOPE, CLOSE_SCOPE, OPENTAG, CLOSETAG, ENDTAG, SPECIAL_PARAM, INPUT_PARAM, PRIVATE_PARAM, TEMPLATE, NIL_TRUE_TAG;

	static {
		CLOSE_SCOPE = "}";
		OPEN_SCOPE = "{";
		PARAM_IDENTIFY = "$";
		SPECIAL_PARAM = "$$";
		OPENTAG = "<";
		CLOSETAG = ">";
		ENDTAG = "/";
		NIL_TRUE_TAG = " i:nil=\"true\"/>";
		INPUT_PARAM = "@i_";
		PRIVATE_PARAM = "@p_";
		TEMPLATE = "@p_template";
	}

	private Map<String, String> source;
	private String requestBase;

	public XMLTransformer(Map<String, String> source, String requestBase) {
		this.source = source;
		if(requestBase != null)
			this.requestBase = requestBase;
		else
			this.requestBase = source.get(TEMPLATE);
	}

	public String replaceBlocks() {
		String res = null;
		String[] splited = null;
		if (this.requestBase.contains(SPECIAL_PARAM)) {
			splited = this.requestBase.split("\\" + PARAM_IDENTIFY + "\\" + PARAM_IDENTIFY);
			this.requestBase = overrideParams(splited);
			this.replaceBlocks();
		}
		if (this.requestBase.contains(PARAM_IDENTIFY)) {
			splited = this.requestBase.split("\\" + PARAM_IDENTIFY);
			res = overrideParams(splited);
		}
		return res;
	}

	private String overrideParams(String[] splited) {
		String res = "";
		for (int i = 0; i < splited.length; i++) {
			res += replace(splited[i]);
		}
		return res;
	}

	private String replace(String part) {
		if (part.contains(OPEN_SCOPE) && part.contains(CLOSE_SCOPE)) {
			String parameterName = part.substring(part.indexOf(OPEN_SCOPE) + 1, part.indexOf(CLOSE_SCOPE));
			return part.replace(OPEN_SCOPE + parameterName + CLOSE_SCOPE, makeTag(parameterName));
		} else {
			return part;
		}
	}

	/**
	 * Convierte la expresion ${parametro} en un tag de nombre "parametro" con el correspondiente value que tiene en el mapa
	 * <p>
	 * si el parametro no empieza con @i_ sera ignorado
	 * </p>
	 * 
	 * @param parameterName
	 * @return
	 */
	private String makeTag(String parameterName) {
		String tag = "";
		if (parameterName.startsWith("#")) {
			tag = this.source.get(PRIVATE_PARAM + parameterName.replace("#", ""));
		} else if (!this.source.containsKey(INPUT_PARAM + parameterName) || this.source.get(INPUT_PARAM + parameterName).isEmpty()) {
			tag = OPENTAG + parameterName + NIL_TRUE_TAG ;
		} else {
			String value = this.source.get(INPUT_PARAM + parameterName);
			tag = OPENTAG + parameterName + CLOSETAG + value + OPENTAG + ENDTAG + parameterName + CLOSETAG;
		}
		return tag;
	}

}