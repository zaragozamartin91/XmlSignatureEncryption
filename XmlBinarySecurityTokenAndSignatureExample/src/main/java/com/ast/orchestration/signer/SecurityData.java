package com.ast.orchestration.signer;

public class SecurityData {
	private String keystoreType;
	private String keystorefilePath;
	private String keystorePass;
	private String alias;
	private String aliasPass;
	private String headerAction;
	private String headerAddress;
	private String headerTo;
	private String headerTimestampExpiration;
	private String headerKeyInfo;

	public SecurityData(String keystoreType, String keystorefilePath, String keystorePass, String alias, String aliasPass, String headerAction,
			String headerAddress, String headerTo, String headerTimestampExpiration, String headerKeyInfo) {
		this.keystoreType = keystoreType;
		this.keystorefilePath = keystorefilePath;
		this.keystorePass = keystorePass;
		this.alias = alias;
		this.aliasPass = aliasPass;
		this.headerAction = headerAction;
		this.headerAddress = headerAddress;
		this.headerTo = headerTo;
		this.headerTimestampExpiration = headerTimestampExpiration;
		this.headerKeyInfo = headerKeyInfo;
	}

	public String getKeystoreType() {
		return keystoreType;
	}

	public void setKeystoreType(String keystoreType) {
		this.keystoreType = keystoreType;
	}

	public String getKeystorefilePath() {
		return keystorefilePath;
	}

	public void setKeystorefilePath(String keystorefilePath) {
		this.keystorefilePath = keystorefilePath;
	}

	public String getKeystorePass() {
		return keystorePass;
	}

	public void setKeystorePass(String keystorePass) {
		this.keystorePass = keystorePass;
	}

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public String getAliasPass() {
		return aliasPass;
	}

	public void setAliasPass(String aliasPass) {
		this.aliasPass = aliasPass;
	}

	public String getHeaderAction() {
		return headerAction;
	}

	public void setHeaderAction(String headerAction) {
		this.headerAction = headerAction;
	}

	public String getHeaderAddress() {
		return headerAddress;
	}

	public void setHeaderAddress(String headerAddress) {
		this.headerAddress = headerAddress;
	}

	public String getHeaderTo() {
		return headerTo;
	}

	public void setHeaderTo(String headerTo) {
		this.headerTo = headerTo;
	}

	public String getHeaderTimestampExpiration() {
		return headerTimestampExpiration;
	}

	public void setHeaderTimestampExpiration(String headerTimestampExpiration) {
		this.headerTimestampExpiration = headerTimestampExpiration;
	}

	public String getHeaderKeyInfo() {
		return headerKeyInfo;
	}

	public void setHeaderKeyInfo(String headerKeyInfo) {
		this.headerKeyInfo = headerKeyInfo;
	}

	@Override
	public String toString() {
		return "SecurityData [keystoreType=" + keystoreType + ", keystorefilePath=" + keystorefilePath + ", keystorePass=" + keystorePass + ", alias=" + alias
				+ ", aliasPass=" + aliasPass + ", headerAction=" + headerAction + ", headerAddress=" + headerAddress + ", headerTo=" + headerTo
				+ ", headerTimestampExpiration=" + headerTimestampExpiration + ", headerKeyInfo=" + headerKeyInfo + "]";
	}

}
