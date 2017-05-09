package com.ast.orchestration.util;

import java.util.HashMap;
import java.util.Map;

import com.cobiscorp.cobis.cts.domains.IProcedureParam;
import com.cobiscorp.cobis.cts.domains.IProcedureRequest;
import com.cobiscorp.cobis.cts.domains.sp.IResultSetRow;
import com.cobiscorp.cobis.cts.domains.sp.IResultSetRowColumnData;

public class ParameterUtil {
	
	/**
	 * Filters out unnecessary parameters for the connector request.
	 * 
	 */
	public IProcedureRequest filterParams(IProcedureRequest anOriginalRequest){
		
		IProcedureRequest request = anOriginalRequest.clone();
		for (Object p : anOriginalRequest.getParams()) {
			IProcedureParam parameterRequest = (IProcedureParam) p;
			if (parameterRequest.getName().startsWith("@i_") || 
				parameterRequest.getName().startsWith("@s_") ||
				parameterRequest.getName().startsWith("@config_") ||
				parameterRequest.getName().startsWith("@complex_")) {
					request.removeParam(parameterRequest.getName());
			}
		}			
		return request;
	}
	
	/**
	 * Return specif parameter of request.
	 * 
	 */
	public String getParam(String param, IProcedureRequest anOriginalRequest){
		
		for (Object p : anOriginalRequest.getParams()) {
			IProcedureParam parameterRequest = (IProcedureParam) p;
			if (param.equals(parameterRequest.getName())){
				return parameterRequest.getValue();			
			}
		}			
		return null;
	}
	
	/**
	 * Creates a map with the position and the number of resultset to merge
	 * 
	 */
	public Map<Integer,Integer> getDataMerge(IProcedureRequest anOriginalRequest){
		
		String[] dataMerge = anOriginalRequest.readParam(Constant.P_MERGE).getValue().split("\\|");	
		Map<Integer,Integer> dataMap = new HashMap<Integer,Integer>();
		
		for(int i=0; i<dataMerge.length;i++){	
			String[] valueMerge = dataMerge[i].split(",");
			dataMap.put(Integer.parseInt(valueMerge[0]), Integer.parseInt(valueMerge[1]));
		}
		return dataMap;
	}
	
	public boolean isEmpty(IResultSetRow[] resultsetRow){
			
		for(IResultSetRow resultset : resultsetRow){
			for(IResultSetRowColumnData colum : resultset.getColumnsAsArray()){
				 if(colum.getValue()!= ""){
					 return false;
				 }			
			}		
		}			
		return true;
	}
}
