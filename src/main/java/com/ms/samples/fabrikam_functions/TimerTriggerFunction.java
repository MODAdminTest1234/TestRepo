package com.ms.samples.fabrikam_functions;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Logger;

import org.json.JSONArray;
import org.json.JSONObject;

import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.TimerTrigger;

public class TimerTriggerFunction {
	
	private static final String CLASSNAME = TimerTriggerFunction.class.getName();
	
	private static final int RESPONSE_CODE_SUCCESS = 200;
	private static final int CONNECT_TIMEOUT = 50000;
	private static final int READ_TIMEOUT = 50000;

	private static final String AUTHENTICATION_TYPE = "client_credentials";
	private static final String CLIENT_ID = "7bd25aad-62a4-462d-ac8e-cda75ab0bdb8";
	private static final String CLIENT_SECRET = "jyJ8Q~zd9q-V7zYS~0bJWpAMwsOUr6gYckgHjahp";
	private static final String AUTHENTICATION_SERVER_URL = 
			"https://login.microsoftonline.com/06caaa28-2cc4-4acf-bdec-da72ef57edc3/oauth2/v2.0/token";
	private static final String REDIRECT_URI = "https://graph.microsoft.com/";
	private static final String SCOPE = "https://graph.microsoft.com/.default";
	private static final String GRAPH_MSFT_COM_USERS_END_POINT = "https://graph.microsoft.com/v1.0/users?$select=assignedLicenses,userType,"
			+ "displayName,givenName,userPrincipalName,id,city,usageLocation,accountEnabled,mailNickname,surname,mail,"
			+ "onPremisesExtensionAttributes,businessPhones,companyName,department,employeeId,faxNumber,jobTitle,mobilePhone,"
			+ "officeLocation,passwordProfile,postalCode,preferredLanguage,state,streetAddress,createdDateTime,"
			+ "country&$count=true&ConsistencyLevel=eventual&$top=20";
	private static final String GRAPH_MSFT_COM_AUDITLOGS_SIGNINS = "https://graph.microsoft.com/v1.0/auditLogs/signIns/";
	private static final String PAGE_TOKEN_ATTRIBUTE = "@odata.nextLink";
	
	private static final String DISABLEMENT_PERIOD = "DISABLEMENT_PERIOD";
	private static final String DELETION_PERIOD = "DELETION_PERIOD";
	
	private static final String ACCESS_TOKEN_ATTRIBUTE = "access_token";
	private static final String REFRESH_TOKEN_ATTRIBUTE = "ext_expires_in";
	private static final String TOKEN_TYPE_ATTRIBUTE = "token_type";
	private static final String EXPIRES_IN_ATTRIBUTE = "expires_in";
	
	private static final String ISO8601_DATE_FORMAT = "YYYY-MM-dd'T'hh:mm:ss";
	
	private Logger logger = null;

	@FunctionName("AsyncLifeCycleManagement")
	public void asyncLifeCycleManagement(
			@TimerTrigger(
				name = "timerInfo",
				schedule = "%TIMER_SCHEDULE%"
			) String timerInfo,
			ExecutionContext context) {
		
		String logp = CLASSNAME + "/asyncLifeCycleManagement;";
		logger = context.getLogger();
		logger.info(logp + "Java TimerTriggerFunction processed a request.");
		try {
			process();
		} catch (Exception e) {
			logger.info(logp + "e.getClass() = " + e.getClass() + ";e.getMessage() = " + e.getMessage()  );
		}		
	}
	
	private void process() {
		String logp = CLASSNAME + "/process;";
		logger.info(logp + "Entered");
    	logger.info("This is a simulation of 30-90 Job.");
    	logger.info("If the user has not logged in last 30 days, they will be receiving warning notifications about Pending Disablement.");
    	logger.info("If the user has not logged in last 90 days, their managers will be receiving warning notifications about Pending Deletion.");

		Map<String, String> envMap = System.getenv();

		String grantType = AUTHENTICATION_TYPE;
		String client_id = CLIENT_ID;
		String clientSecret = CLIENT_SECRET;
		String authenticationServerUrl = AUTHENTICATION_SERVER_URL;
		String redirect_uri = REDIRECT_URI;
		String scope = SCOPE;
		String usersEndPoint = GRAPH_MSFT_COM_USERS_END_POINT;
		String auditLogsEndPoint = GRAPH_MSFT_COM_AUDITLOGS_SIGNINS;
		String pageTokenAttribute = PAGE_TOKEN_ATTRIBUTE;
		
		String disablementPeriodStr = envMap.get(DISABLEMENT_PERIOD);
		String deletionPeriodStr = envMap.get(DELETION_PERIOD);
		logger.info(logp + "disablementPeriodStr = " + disablementPeriodStr + 
				"; deletionPeriodStr = " + deletionPeriodStr);
		
		int disablementPeriod = 0;
		if(!isNullOrEmpty(disablementPeriodStr)) {
			try {
				disablementPeriod = Integer.parseInt(disablementPeriodStr);
			} catch (NumberFormatException e) {
				throw new RuntimeException("Invalid DISABLEMENT_PERIOD", e);
			}
		}		
		int deletionPeriod = 0;
		if(!isNullOrEmpty(deletionPeriodStr)) {
			try {
				deletionPeriod = Integer.parseInt(deletionPeriodStr);
			} catch (NumberFormatException e) {
				throw new RuntimeException("Invalid DELETION_PERIOD", e);
			}
		} 
		if((disablementPeriod <= 0) || (deletionPeriod <= 0) || (deletionPeriod <= disablementPeriod)) {
			throw new RuntimeException("Invalid DISABLEMENT_PERIOD / DELETION_PERIOD");
		}
		
		SimpleDateFormat simpleDateFormat = new SimpleDateFormat(ISO8601_DATE_FORMAT);
		Calendar calendar = Calendar.getInstance();
		String nowDate = simpleDateFormat.format(calendar.getTime()) + "Z";
		
		if(disablementPeriod >= 0) { disablementPeriod = (-1) * disablementPeriod ;}
		calendar.add(Calendar.DATE, disablementPeriod);
		String disablementPeriodDate = simpleDateFormat.format(calendar.getTime()) + "Z";
		
		if(deletionPeriod >= 0) { deletionPeriod = (-1) * deletionPeriod ;}
		calendar = Calendar.getInstance();
		calendar.add(Calendar.DATE, deletionPeriod);
		String deletionPeriodDate = simpleDateFormat.format(calendar.getTime()) + "Z";
		logger.info(logp + "nowDate = " + nowDate + "; disablementPeriodDate = " + disablementPeriodDate  + 
				"; deletionPeriodDate = " + deletionPeriodDate);
		
		HashMap<String, String> accessTokenMap = 
				getAccessTokenMap(grantType, client_id, clientSecret, authenticationServerUrl, redirect_uri, scope);
		String accessToken = accessTokenMap.get(ACCESS_TOKEN_ATTRIBUTE);
		
		String url = usersEndPoint;
		List<HashMap<String, String>> userMapList = getAllUsers(accessToken, url, pageTokenAttribute);		
		logger.info(logp + "userMapList.size() = " + userMapList.size());
		
		url = auditLogsEndPoint;
		List<HashMap<String, String>> auditSignInsList = getAuditSignIns(accessToken, url, pageTokenAttribute);
		logger.info(logp + "auditSignInsList.size() = " + auditSignInsList.size());
		
		HashMap<String, String> userIdVsUserPrincipalNameFromAuditLogsMap = new HashMap<String, String>();
		
		HashMap<String, String> userIdVsLastLoginTimeStampMap = new HashMap<String, String>();
		HashMap<String, String> userPrincipalNameVsLastLoginTimeStampMap = new HashMap<String, String>();
		HashMap<String, TreeSet<String>> userIdVsLastLoginTimeStampSetMap = new HashMap<String, TreeSet<String>>();
		
		String userPrincipalName = null;
		String createdDateTime = null;
		String accountEnabled = null;
		
		/**
		 * In the Audit Log, the user's id is referred to as userId. And createdDateTime refers to the Sign In.
		 */
		String userId = null;
		String lastLoginTimeStamp = null;
		TreeSet<String> lastLoginTimeStampsSet = null;
		
		for(HashMap<String, String> auditSignInsMap : auditSignInsList) {
			if(null == auditSignInsMap || auditSignInsMap.isEmpty()) {
				continue;
			}
			userId = auditSignInsMap.get("userId");
			userPrincipalName = auditSignInsMap.get("userPrincipalName");			
			lastLoginTimeStamp = auditSignInsMap.get("createdDateTime");
			
			if(isNullOrEmpty(userId) || isNullOrEmpty(userPrincipalName) || isNullOrEmpty(lastLoginTimeStamp)) {
				continue;
			}
			userIdVsUserPrincipalNameFromAuditLogsMap.put(userId, userPrincipalName);
			
			lastLoginTimeStampsSet = userIdVsLastLoginTimeStampSetMap.get(userId);
			if(null == lastLoginTimeStampsSet) {
				lastLoginTimeStampsSet = new TreeSet<String>();
				userIdVsLastLoginTimeStampSetMap.put(userId, lastLoginTimeStampsSet);
			}
			lastLoginTimeStampsSet.add(lastLoginTimeStamp);
		}
		Set<Map.Entry<String, TreeSet<String>>> userIdVsLastLoginTimeStampSetMapEntrySet = userIdVsLastLoginTimeStampSetMap.entrySet();
		for(Map.Entry<String, TreeSet<String>> userIdVsLastLoginTimeStampSetMapEntry : userIdVsLastLoginTimeStampSetMapEntrySet) {
			userId = userIdVsLastLoginTimeStampSetMapEntry.getKey();
			lastLoginTimeStampsSet = userIdVsLastLoginTimeStampSetMapEntry.getValue();
			if(isNullOrEmpty(userId) || lastLoginTimeStampsSet == null || lastLoginTimeStampsSet.isEmpty()) {
				continue;
			}
			lastLoginTimeStamp = lastLoginTimeStampsSet.last();
			userIdVsLastLoginTimeStampMap.put(userId, lastLoginTimeStamp);
			userPrincipalName = userIdVsUserPrincipalNameFromAuditLogsMap.get(userId);
			userPrincipalNameVsLastLoginTimeStampMap.put(userPrincipalName, lastLoginTimeStamp);
		}
		TreeMap<String, String> userPrincipalNameVsLastLoginTimeStampTreeMap = 
				new TreeMap<String, String>(userPrincipalNameVsLastLoginTimeStampMap);

		logger.info(logp + "User Principal Name vs Last Login Time Stamp: \n" + 
				printMapWithNewLine(userPrincipalNameVsLastLoginTimeStampTreeMap));
		logger.info(logp + "-------------------------------------------------------------------------------------------------");
		String lastActivityDateTime = null;
		boolean isAccountEnabled = false;
		
		HashMap<String, String> accountsToBeDisabledMap = new HashMap<String, String>();
		HashMap<String, String> accountsToBeDeletedMap = new HashMap<String, String>(); 
		
		TreeMap<String, String> userPrincipalNameVsLastActivityDateTreeMap = new TreeMap<String, String>();
		
		for(HashMap<String, String> userMap : userMapList) {
			if(null == userMap || userMap.isEmpty()) {
				continue;
			}
			userId = userMap.get("id");
			userPrincipalName = userMap.get("userPrincipalName");
			createdDateTime = userMap.get("createdDateTime");
			accountEnabled = userMap.get("accountEnabled");
			lastLoginTimeStamp = userIdVsLastLoginTimeStampMap.get(userId);
			
			isAccountEnabled = "TRUE".equalsIgnoreCase(accountEnabled);
			
			if(!isNullOrEmpty(lastLoginTimeStamp)) {
				lastActivityDateTime = lastLoginTimeStamp;
			} else {
				lastActivityDateTime = createdDateTime;
			}
			userPrincipalNameVsLastActivityDateTreeMap.put(userPrincipalName, lastActivityDateTime);
			if( lastActivityDateTime.compareTo(deletionPeriodDate) < 0 ) {
				if(isAccountEnabled) {
					accountsToBeDisabledMap.put(userId, userPrincipalName);
				} else {
					accountsToBeDeletedMap.put(userId, userPrincipalName);
				}
			} else if( lastActivityDateTime.compareTo(disablementPeriodDate) < 0 ) {
				if(isAccountEnabled) {
					accountsToBeDisabledMap.put(userId, userPrincipalName);
				} 
			}			
		}
		logger.info(logp + "User Principal Name vs Last Activity: \n " + printMapWithNewLine(userPrincipalNameVsLastActivityDateTreeMap));
		logger.info(logp + "-------------------------------------------------------------------------------------------------");
		logger.info(logp + "Accounts to be disabled: \n " + printMapWithNewLine(accountsToBeDisabledMap));
		logger.info(logp + "-------------------------------------------------------------------------------------------------");
		logger.info(logp + "Accounts to be deleted: \n" + printMapWithNewLine(accountsToBeDeletedMap));
	}
		
	private HashMap<String, String> getAccessTokenMap( String grantType, String client_id, String clientSecret, 
			String authenticationServerUrl, String redirect_uri, String scope) {
		String logp = CLASSNAME + "/getAccessTokenMap;";
		logger.info(logp + "Entering. grantType = " + grantType + "; client_id = " + client_id + 
				"; clientSecret = **** " + "; authenticationServerUrl = " + authenticationServerUrl + 
				"; redirect_uri = " + redirect_uri + "; scope = " + scope);
		
	    HashMap<String, String> accessTokenMap = null;
	    BufferedReader in = null;
	    OutputStreamWriter out = null;
		try {
			URL url = new URL(authenticationServerUrl);
			System.out.println(logp + "URL :-" + url);
		    HttpURLConnection connection = (HttpURLConnection)url.openConnection();
		    connection.setRequestMethod("POST");
		    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		    connection.setConnectTimeout(CONNECT_TIMEOUT);
		    connection.setDoOutput(true);
		    connection.setReadTimeout(READ_TIMEOUT);
		    out = new OutputStreamWriter(connection.getOutputStream());
		    
		    String parameters = new StringBuilder()
		    		.append("grant_type=").append(grantType)
		    		.append("&redirect_uri=").append(redirect_uri)
		    		.append("&client_id=").append(client_id)
		    		.append("&client_secret=").append(clientSecret)
		    		.append("&scope=").append(scope)
		    		.toString();
		    
		    out.write(parameters);	
		    close(out);
		    
		    in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
		    String gline = "";
		    for (String line = in.readLine(); line != null; line = in.readLine()) {
		    	gline = line;
		    }
		    if (connection.getResponseCode() != RESPONSE_CODE_SUCCESS) {
		    	System.out.println(logp + "Error while Generating Access Code");
		    	return null;
		    }
	    	JSONObject parseJsonObj = new JSONObject(gline);
	    	accessTokenMap = new HashMap<String, String>();
	    	System.out.println(parseJsonObj.toString(4));
	    	if (parseJsonObj.has(ACCESS_TOKEN_ATTRIBUTE)) {
	    		accessTokenMap.put(ACCESS_TOKEN_ATTRIBUTE, parseJsonObj.get(ACCESS_TOKEN_ATTRIBUTE).toString());
	    	}
	    	if (parseJsonObj.has(REFRESH_TOKEN_ATTRIBUTE)) {
	    		accessTokenMap.put(REFRESH_TOKEN_ATTRIBUTE, parseJsonObj.get(REFRESH_TOKEN_ATTRIBUTE).toString());
	    	}
	    	if (parseJsonObj.has(TOKEN_TYPE_ATTRIBUTE)) {
	    		accessTokenMap.put(TOKEN_TYPE_ATTRIBUTE, parseJsonObj.get(TOKEN_TYPE_ATTRIBUTE).toString());
	    	}
	    	if (parseJsonObj.has(EXPIRES_IN_ATTRIBUTE)) {
	    		accessTokenMap.put(EXPIRES_IN_ATTRIBUTE, parseJsonObj.get(EXPIRES_IN_ATTRIBUTE).toString());
	    	}
		} catch (Exception e) {
			System.err.println(logp + "Exception occurred " + e.getClass() + "; " + e.getMessage());
			e.printStackTrace();
	    } finally {
	    	close(in);	    	
	    }
		logger.info(logp + "Exiting with accessTokenMap");
		return accessTokenMap;
	}
	
	private List<HashMap<String, String>> getAllUsers(String accessToken, String url, String pageTokenAttribute) { 
		String logp = CLASSNAME + "/getAllUsers;";
		logger.info(logp + "Entering"+ ";url = " + url);
		List<HashMap<String, String>> userMapList = new ArrayList<HashMap<String, String>>();
		if(isNullOrEmpty(accessToken)){
			logger.info(logp + "INVALID_ACCESS_TOKEN");
			return userMapList;
		}
		if(isNullOrEmpty(url)){
			logger.info(logp + "INVALID_URL");
			return userMapList;
		}
		if(isNullOrEmpty(pageTokenAttribute)){
			logger.info(logp + "INVALID_PAGE_TOKEN_ATTRIBUTE");
			return userMapList;
		}
		try {
			String token = "Bearer " + accessToken;
			URL obj = new URL(url);        

			HttpURLConnection connection =(HttpURLConnection)obj.openConnection();  
			if(connection == null){
				return userMapList;
			} 
			connection.setRequestMethod("GET");
			connection.setRequestProperty("Authorization", token);
			connection.setRequestProperty("Accept", "application/json");
			connection.setRequestProperty("Content-Type", "application/json");
			connection.setConnectTimeout(CONNECT_TIMEOUT);
			connection.setDoOutput(true);
			connection.setReadTimeout(READ_TIMEOUT);
			int responseCode = connection.getResponseCode();
			logger.info(logp + "responseCode :" + responseCode);			
			if(! (RESPONSE_CODE_SUCCESS == responseCode)){
				logger.info(logp + "Some error happened while searching.");
				return userMapList;
			}
			BufferedReader bufferedReader = null;
			String odataLink = null;
			Object valueObj = null;
			do {
				if(!isNullOrEmpty(odataLink)){
					url = odataLink;
				}
				obj = new URL(url);				
				connection =(HttpURLConnection)obj.openConnection();  
				if(connection == null){
					return userMapList;
				}  
				connection.setRequestMethod("GET");
				connection.setRequestProperty("Authorization", token);
				connection.setRequestProperty("Accept", "application/json");
				connection.setRequestProperty("Content-Type", "application/json");
				connection.setConnectTimeout(CONNECT_TIMEOUT);
				connection.setDoOutput(true);
				connection.setReadTimeout(READ_TIMEOUT);
				responseCode = connection.getResponseCode();
				if(!(RESPONSE_CODE_SUCCESS == responseCode)){
					logger.info(logp + "responseCode :" + responseCode);
					return userMapList;
				}
				try {
					bufferedReader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
					String input = null;
			        StringBuilder response = new StringBuilder();
					while (true){
						input = bufferedReader.readLine();
						if(null == input) {
							break;
						}
						response.append(input);
					}
					JSONObject jsonObject = new JSONObject(response.toString());
					if(jsonObject.has("value")) {
						valueObj = jsonObject.get("value");
					}
					if((null != valueObj) && (valueObj instanceof JSONArray)){
						JSONArray jsonArray = (JSONArray) valueObj;
						userMapList.addAll(getListOfHashMapOfStringFromJSONArray(jsonArray));
					}
					if(jsonObject.has(pageTokenAttribute)) {
						valueObj = jsonObject.get(pageTokenAttribute);
					}
					odataLink = null;
					if((null != valueObj) && (valueObj instanceof String)){
						odataLink = valueObj.toString().trim();
					}
				} catch (Exception e) {
					logger.info(logp + "Exception occurred " + e.getClass() + "; " + e.getMessage());
				} finally {
					close(bufferedReader);
				}
			} while (!isNullOrEmpty(odataLink));			
		} catch (Exception e) {
			logger.info(logp + "Exception occurred " + e.getClass() + "; " + e.getMessage());
		}
        return userMapList;
    }

	private List<HashMap<String, String>> getAuditSignIns(String accessToken, String url, String pageTokenAttribute) { 
		String logp = CLASSNAME + "/getAuditSignIns;";
		logger.info(logp + "Entering"+ ";url = " + url);
		List<HashMap<String, String>> userMapList = new ArrayList<HashMap<String, String>>();
		if(isNullOrEmpty(accessToken)){
			logger.info(logp + "INVALID_ACCESS_TOKEN");
			return userMapList;
		}
		if(isNullOrEmpty(url)){
			logger.info(logp + "INVALID_URL");
			return userMapList;
		}
		if(isNullOrEmpty(pageTokenAttribute)){
			logger.info(logp + "INVALID_PAGE_TOKEN_ATTRIBUTE");
			return userMapList;
		}
		try {
			String token = "Bearer " + accessToken;
			URL obj = new URL(url);        

			HttpURLConnection connection =(HttpURLConnection)obj.openConnection();  
			if(connection == null){
				return userMapList;
			} 
			connection.setRequestMethod("GET");
			connection.setRequestProperty("Authorization", token);
			connection.setRequestProperty("Accept", "application/json");
			connection.setRequestProperty("Content-Type", "application/json");
			connection.setConnectTimeout(CONNECT_TIMEOUT);
			connection.setDoOutput(true);
			connection.setReadTimeout(READ_TIMEOUT);
			int responseCode = connection.getResponseCode();
			logger.info(logp + "responseCode :" + responseCode);			
			if(! (RESPONSE_CODE_SUCCESS == responseCode)){
				logger.info(logp + "Some error happened while searching.");
				return userMapList;
			}
			BufferedReader bufferedReader = null;
			String odataLink = null;
			Object valueObj = null;
			do {
				if(!isNullOrEmpty(odataLink)){
					url = odataLink;
				}
				obj = new URL(url);				
				connection =(HttpURLConnection)obj.openConnection();  
				if(connection == null){
					return userMapList;
				}  
				connection.setRequestMethod("GET");
				connection.setRequestProperty("Authorization", token);
				connection.setRequestProperty("Accept", "application/json");
				connection.setRequestProperty("Content-Type", "application/json");
				connection.setConnectTimeout(CONNECT_TIMEOUT);
				connection.setDoOutput(true);
				connection.setReadTimeout(READ_TIMEOUT);
				responseCode = connection.getResponseCode();
				if(!(RESPONSE_CODE_SUCCESS == responseCode)){
					logger.info(logp + "responseCode :" + responseCode);
					return userMapList;
				}
				try {
					bufferedReader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
					String input = null;
			        StringBuilder response = new StringBuilder();
					while (true){
						input = bufferedReader.readLine();
						if(null == input) {
							break;
						}
						response.append(input);
					}
					JSONObject jsonObject = new JSONObject(response.toString());
					if(jsonObject.has("value")) {
						valueObj = jsonObject.get("value");
					}
					if((null != valueObj) && (valueObj instanceof JSONArray)){
						JSONArray jsonArray = (JSONArray) valueObj;
						userMapList.addAll(getListOfHashMapOfStringFromJSONArray(jsonArray));
					}
					if(jsonObject.has(pageTokenAttribute)) {
						valueObj = jsonObject.get(pageTokenAttribute);
					}
					odataLink = null;
					if((null != valueObj) && (valueObj instanceof String)){
						odataLink = valueObj.toString().trim();
					}
				} catch (Exception e) {
					logger.info(logp + "Exception occurred " + e.getClass() + "; " + e.getMessage());
				} finally {
					close(bufferedReader);
				}
			} while (!isNullOrEmpty(odataLink));			
		} catch (Exception e) {
			logger.info(logp + "Exception occurred " + e.getClass() + "; " + e.getMessage());
		}
        return userMapList;
    }

	private HashMap<String, String> getHashMapOfStringFromJSONObject(JSONObject jsonObject){
		if(null == jsonObject) {
			return null;
		}
		Set<String> keySet = jsonObject.keySet();
		Object object = null;
		HashMap<String, String> hashMap = new HashMap<String, String>();		
		for(String key : keySet){
			object = jsonObject.get(key);
			if(null == object) {
				hashMap.put(key, null);
				continue;
			}
			if(object instanceof String) {
				hashMap.put(key, (String) object);
				continue;
			} else if(object instanceof JSONObject) {
				hashMap.put(key, ((JSONObject) object).toString());
				continue;
			} else if(object instanceof JSONArray) {
				hashMap.put(key, ((JSONArray) object).toString());
				continue;
			} else {
				hashMap.put(key, object.toString());
				continue;
			}
		}
		return hashMap;
	}

	private HashMap<String, Object> getHashMapFromJSONObject(JSONObject jsonObject){
		if(null == jsonObject) {
			return null;
		}
		Set<String> keySet = jsonObject.keySet();
		Object object = null;
		HashMap<String, Object> hashMap = new HashMap<String, Object>();
		
		for(String key : keySet){
			object = jsonObject.get(key);
			if(null == object) {
				hashMap.put(key, null);
				continue;
			}
			if(object instanceof String) {
				hashMap.put(key, (String) object);
				continue;
			}
			if(object instanceof JSONObject) {
				hashMap.put(key, getHashMapFromJSONObject((JSONObject) object)) ;
				continue;
			}
			if(object instanceof JSONArray) {
				hashMap.put(key, getListFromJSONArray((JSONArray) object));
				continue;
			}
		}
		return hashMap;
	}
	
	private List<Object> getListFromJSONArray(JSONArray jsonArray){
		if(null == jsonArray) {
			return null;
		}
		List<Object> array = new ArrayList<Object>();
		int length = jsonArray.length();
		Object object = null;
		for(int i = 0; i < length; i++){
			object = jsonArray.get(i);
			if(null == object){
				array.add(i, null);
				continue;
			} else if(object instanceof String) {
				array.add(i, (String) object);
			} else if(object instanceof JSONObject) {
				array.add(i, getHashMapFromJSONObject((JSONObject)object));
			} else if(object instanceof JSONArray) {
				array.add(i, getListFromJSONArray((JSONArray)object));
			} 
		}
		return array;
	}
	
	private List<HashMap<String, String>> getListOfHashMapOfStringFromJSONArray(JSONArray jsonArray){
		List<HashMap<String, String>> array = null;;
		if(null == jsonArray) {
			return array;
		}
		array = new ArrayList<HashMap<String, String>>();
		int length = jsonArray.length();
		Object object = null;
		for(int i = 0; i < length; i++){
			object = jsonArray.get(i);
			if(null == object){
				array.add(i, null);
				continue;
			} else if(object instanceof JSONObject) {
				array.add(i, getHashMapOfStringFromJSONObject((JSONObject)object));
			} else if(object instanceof JSONArray) {
				array.addAll(i, getListOfHashMapOfStringFromJSONArray((JSONArray)object));
			} else {
				HashMap<String, String> hashMap = new HashMap<String, String>();
				hashMap.put(object.toString().trim(), object.toString().trim());
				array.add(i, hashMap);
			}
		}
		return array;
	}

	private void close(Closeable closeable){
		String logp = CLASSNAME + "/close;";
		if(null == closeable) {
			return;
		}
		try {
			closeable.close();
		} catch (IOException e) {
			System.err.println(logp + "Exception occurred " + e.getClass() + "; " + e.getMessage());
		}
	}
	
	private String printMapWithNewLine(Map<String, String> map) {
		if(null == map) {
			return null;
		}
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append('{').append('\n');
		Set<Map.Entry<String, String>> entrySet = map.entrySet();
		int count = 0;
		for(Map.Entry<String, String> entry : entrySet) {
			stringBuilder.append(++count).append(") ").append(entry.getKey()).append(" = ").append(entry.getValue()).append(", \n");
		}
		stringBuilder.append('}');	
		return stringBuilder.toString();
	}
	
	private boolean isNullOrEmpty(String str) {
		return (str == null) || (str.trim().isEmpty());
	}
	
}
