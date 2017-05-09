package com.ast.orchestration.util;

public class XMLUtil {
	@Deprecated
	public String replaceLabels(String originalXml) throws Exception {	
		
		String xml = originalXml.replaceAll("\\[", "<").replaceAll("'", "\"");
		xml = xml.replaceAll("\\]", ">");
		
		return xml;
	}
	
	@Deprecated
	public String makeComplexParam(String structure, String source) throws Exception  {

		structure = structure.replaceAll("\\[", "<");
		structure = structure.replaceAll("\\]", ">");
		String resultado = "";
		String attrSeparator = ",";// se recomienda
		String itemSeparator = "\\|";

		String[] itemArray = source.split(itemSeparator);
		for (int i = 0; i < itemArray.length; i++) {
			itemArray[i] = itemArray[i] + ".";
		}
		for (String itemSource : itemArray) {
			String[] tagValues = itemSource.split(attrSeparator);
			String[] tags = structure.split("#");
			resultado += tags[0];
			tagValues[tagValues.length - 1] = tagValues[tagValues.length - 1].substring(0, tagValues[tagValues.length - 1].length() - 1);

			for (int i = 0; i < tags.length && i < tagValues.length; i++) {
				resultado += tagValues[i] + tags[i + 1];
			}
		}

		return resultado;
	}
	
	public String makeComplex(String structure, String source) throws Exception {

		String[] tagPadre = structure.split("\\|");	
		String[] tagHijo = tagPadre[1].split(",");
		String[] valueHijo = source.split("\\|");
		
		for (int i = 0; i < valueHijo.length; i++) {
			valueHijo[i] = valueHijo[i] + ",aux";
		}					
		
		StringBuilder builder = new StringBuilder();	
		for(int i=0;i<valueHijo.length;i++){	
			builder.append("<" + tagPadre[0] + ">");				
			String[] value = valueHijo[i].split(",");	
			
			for(int j=0;j<value.length-1;j++){				
				if("".equals(value[j])){
					builder.append("<" + tagHijo[j] + " i:nil=\"true\"/>");
				}else{
					builder.append("<" + tagHijo[j] + ">" + value[j] + "</" + tagHijo[j] + ">");
				}
			}
			builder.append("</" + tagPadre[0] + ">");
		}
			
		return builder.toString();
	}
}
