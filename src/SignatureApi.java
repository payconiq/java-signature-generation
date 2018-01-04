import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * This class is responsible for handeling signature related functionality.
 * 
 * In order to secure the transfer of all transactions, a symmetric signature is
 * generated on Payconiq’s servers and the merchant’s backend. Once generated on
 * both sides, the signature is send to Payconiq to validate the transaction
 * request. Only when both sides recognize the same symmetric signature, a
 * transaction will be considered as valid and will be processed. As we need to
 * generate this key on both sides, secret information needs to be shared
 * between them.
 **/
public class SignatureApi {

	private byte[] sourceByte;

	/**
	 * Constructor for the SignatureApi class.
	 * 
	 * string merchantId : Unique number used to identify merchant within Payconiq
	 * platform, acquired as part of the sign up process string secretKey : Used to
	 * secure communications between merchant and Payconiq string currency :
	 * Generally accepted form of money. For instance "EUR" string amount : Quantity
	 * of money based on the specified currency. For instance "0.01" euro string
	 * webhookId (optional): A simple event-notification id via HTTP POST
	 * 
	 * @throws SignatureGenerationException
	 **/
	public SignatureApi(String merchantId, String secretKey, String currency, String amount, String webhookId)
			throws SignatureGenerationException {
		if (merchantId == null || merchantId.isEmpty()) {

			throw new SignatureGenerationException("Merchant id is a required parameter which should be filled.");
		}
		if (webhookId == null) {
			webhookId = "";
		}
		if (secretKey == null || secretKey.isEmpty()) {

			throw new SignatureGenerationException("Secret key is a required parameter which should be filled.");
		}
		if (currency == null || currency.isEmpty()) {

			throw new SignatureGenerationException("Currency is a required parameter which should be filled.");
		}
		if (amount == null || amount.isEmpty()) {

			throw new SignatureGenerationException("Amount is a required parameter which should be filled.");
		}

		String sourceData = String.format("%s%s%s%s%s", merchantId, webhookId, currency, amount, secretKey);
		this.sourceByte = sourceData.getBytes();
	}

	/**
	 * Generates the signature based on the provided info in the constructor of the
	 * class. string hashAlgorithm : provided hash algorithm to generate the
	 * signature based on that. Note : Other hash algorithms can be set to be used
	 * as well.
	 * 
	 * return string : Generated hash signature based on merchantId, secretKey,
	 * currency, amount, webhookId
	 * 
	 * @throws SignatureGenerationException
	 * @throws NoSuchAlgorithmException
	 **/
	public String generateSignature(String hashAlgorithm)
			throws SignatureGenerationException, NoSuchAlgorithmException {

		MessageDigest digest = MessageDigest.getInstance(SignatureApiConstants.CRYPTOGRAPHIC_HASH_ALGORITHM_SHA256);
		byte[] hash = digest.digest(this.sourceByte);

		// generate signature
		String signature = Base64.getEncoder().encodeToString(hash);

		// check the creation of the singnature
		if (signature == null || signature.isEmpty()) {
			throw new SignatureGenerationException("Signed signature is empty.");
		}

		// return the generated signature
		return signature;

	}

	/**
	 * Verify the provided signature. This function compares the provided signature
	 * with the actual data that is used to generate signatures. string
	 * signatureToBeVerified : Generated hash signature based on merchantId,
	 * secretKey, currency, amount, webhookId string hashAlgorithm : provided hash
	 * algorithm to verify the signature based on that.
	 * 
	 * return bool: true in case of signature verification acceptance; false
	 * otherwise.
	 * 
	 * @throws SignatureGenerationException
	 * @throws NoSuchAlgorithmException
	 **/
	public boolean verifySignature(String signatureToBeVerified, String hashAlgorithm)
			throws NoSuchAlgorithmException, SignatureGenerationException {
		String sourceSignature = this.generateSignature(hashAlgorithm);
		if (sourceSignature.equals(signatureToBeVerified)) {
			return true;
		}
		return false;
	}
}
