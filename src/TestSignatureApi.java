import java.security.NoSuchAlgorithmException;

public class TestSignatureApi {

	public static void main(String[] args) throws SignatureGenerationException, NoSuchAlgorithmException {
		
            String merchantId = "123";
            String secretKey = "SecretKey";
            String currency = "EUR";
            String amount = "1000";
            String webhookId = null;

            // Create instance of the signature api
            SignatureApi signatureApi = new SignatureApi(merchantId, secretKey, currency, amount, webhookId);

            // Signature creation 
            String signature = signatureApi.generateSignature(SignatureApiConstants.CRYPTOGRAPHIC_HASH_ALGORITHM_SHA256);
            System.out.println(signature);

            // Verify the generated signature
            boolean signatureVerified = signatureApi.verifySignature(signature, SignatureApiConstants.CRYPTOGRAPHIC_HASH_ALGORITHM_SHA256);
            System.out.println("Signature is verified? " + signatureVerified);

            // Verify the incorrect signature
            String incorrectSignature = "MTIzRVVSMTAwMFNlY3JldEtleQ11";
            System.out.println("Signature is verified? " + signatureApi.verifySignature(incorrectSignature, SignatureApiConstants.CRYPTOGRAPHIC_HASH_ALGORITHM_SHA256));      
	}


}