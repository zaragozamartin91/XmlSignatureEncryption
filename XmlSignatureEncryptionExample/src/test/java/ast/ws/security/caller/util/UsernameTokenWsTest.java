package ast.ws.security.caller.util;

import ast.ws.security.caller.doc.AstSoapDocument;
import ast.ws.security.util.DocumentUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.ws.security.WSSecurityException;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class UsernameTokenWsTest {
    public static void main(String[] args) throws ParserConfigurationException, WSSecurityException, SAXException, IOException, TransformerException {
        System.setProperty("com.sun.xml.ws.transport.http.client.HttpTransportPipe.dump", "true");
        System.setProperty("com.sun.xml.internal.ws.transport.http.client.HttpTransportPipe.dump", "true");
        System.setProperty("com.sun.xml.ws.transport.http.HttpAdapter.dump", "true");
        System.setProperty("com.sun.xml.internal.ws.transport.http.HttpAdapter.dump", "true");

        System.setProperty("javax.net.ssl.trustStore", "D:\\apache-tomcat-8.5.33\\conf\\clienttruststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");

        String soapMsg = buildSoapMsg();
        System.out.println(soapMsg);

        DefaultHttpClient httpClient = new DefaultHttpClient();

        try {
            //Define a postRequest request
            HttpPost postRequest = new HttpPost("https://localhost:8443/CxfMavenSslUsernametoken-0.0.1/BookRepo");

            //Set the API media type in http content-type header
            postRequest.addHeader("content-type", "application/xml");

            StringEntity requestBody = new StringEntity(soapMsg);
            postRequest.setEntity(requestBody);

            //Send the request; It will immediately return the response in HttpResponse object if any
            HttpResponse response = httpClient.execute(postRequest);

            //verify the valid error code first
            int statusCode = response.getStatusLine().getStatusCode();
            System.out.println("Status code: " + statusCode);

            BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

        } finally {
            //Important: Close the connect
            httpClient.getConnectionManager().shutdown();
        }

    }

    private static String buildSoapMsg() throws ParserConfigurationException, SAXException, IOException, WSSecurityException, TransformerException {
        String payload = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><ns2:getBook xmlns:ns2=\"http://ws.ex.mz/\"><bookRequest><isbn>1234</isbn></bookRequest></ns2:getBook></soap:Body></soap:Envelope>";

        AstSoapDocument astSoapDocument = AstSoapDocument.createFromString(payload)
                .insertSecurityHeader()
                .insertReplyToAddress("http://www.w3.org/2005/08/addressing/anonymous")
                .insertTo("https://localhost:8443/CxfMavenSslUsernametoken-0.0.1/BookRepo")
                .insertRandomMessageId()
                .insertAction("http://ws.ex.mz/BookRepoPortTypeImpl/getBook")
                .insertTimestamp(60 * 5, "TS-")
                .insertUsernameToken("joe", "joespassword");

        return DocumentUtils.documentToString(astSoapDocument.getDoc());
    }
}
