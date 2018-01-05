
/**
 * Class to specify the exceptions which can occur during signature generation
 * or verification
 **/
@SuppressWarnings("serial")
public class SignatureGenerationException extends Exception {

	public SignatureGenerationException(String message) {
		super(message);
	}

}
