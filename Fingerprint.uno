using Uno;
using Uno.UX;
using Uno.Collections;
using Android;
using Uno.Compiler.ExportTargetInterop;
using Fuse;
using Fuse.Scripting;

namespace Fuse.Biometric
{
	public interface IFingerPrint 
	{
		void AuthResult(bool Result, string Msg);

		bool IsSupported();

		void Authenticate(string reason);

		void Stop();
	}

	[UXGlobalModule]
	public class FingerprintModule : NativeModule
	{
		static readonly FingerprintModule _instance;	

		static Context Context;
		static Fuse.Scripting.Function _Callback;

		static IFingerPrint FingerPrint;

		public FingerprintModule()
		{
			if (_instance != null) return;
			
			_instance = this;
			if defined(Android) {
				FingerPrint = new FingerPrintImpl();
			}else if defined(iOS) {
				FingerPrint = new IOSFingerPrintImpl();
			}
			Resource.SetGlobalKey(_instance, "FingerPrint");
			AddMember(new NativeFunction("isSupported", (NativeCallback)IsSupported));
			AddMember(new NativeFunction("auth", (NativeCallback)FingerPrintAuthenticate));
			AddMember(new NativeFunction("stop", (NativeCallback)StopAuthenticate));
		}

		object FingerPrintAuthenticate(Context C, object[] args) 
		{
			Context = C;
			if (args.Length == 0) {
				return null;
			}
			_Callback = args[0] as Fuse.Scripting.Function;			
			if defined(MOBILE) {
				var reason = "";
				if (args.Length == 2)
					reason = args[1] as string;			
				FingerPrint.Authenticate(reason);
			}else {
				Context.Invoke(new InvokeEnclosure(_Callback, false, "Not on iOS or Android").InvokeCallback);
			}
			return null;
		}

		object IsSupported(Context C, object[] args) 
		{
			Context = C;
			if defined(MOBILE) {				
				return FingerPrint.IsSupported();
			}
			return false;	
		}

		object StopAuthenticate(Context C, object[] args)
		{
			Context = C;
			if defined(MOBILE) {
				FingerPrint.Stop();
			}
			return null;
		}

		public static void AuthDone (bool Auth, string S) 
		{
			Context.Invoke(new InvokeEnclosure(_Callback, Auth, S).InvokeCallback);
		}		
	}

	[Require("Xcode.Framework","LocalAuthentication")]
	[Require("Source.Import","LocalAuthentication/LocalAuthentication.h")]
	extern(iOS) class IOSFingerPrintImpl : IFingerPrint
	{

		public void AuthResult(bool Result, string Msg) {
			FingerprintModule.AuthDone(Result, Msg);
		}

		[Foreign(Language.ObjC)]
		public extern(iOS) bool IsSupported() 
		@{
			LAContext *myContext = [[LAContext alloc] init];
	        NSError *authError = nil;
	        return [myContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&authError];
		@}


		[Foreign(Language.ObjC)]
		public extern(iOS) void Authenticate(string reason)
		@{
			LAContext *myContext = [[LAContext alloc] init];
	        NSError *authError = nil;
	        if ([myContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&authError]) {
	            [myContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
	            localizedReason:reason
	            reply:^(BOOL success, NSError *error) {
	                 // Need a pool, since we are running on a different thread
	                uAutoReleasePool pool;
	                NSString * text = nil;
	                if (success)
	                	text = @"Auth Success";
	                else
	                	text = @"Auth Failed";
	                @{FingerprintModule:Of(_this).AuthResult(bool, string):Call(success, text)};
	            }];
	        } else {
	            // Could not evaluate policy; look at authError and present an appropriate message to user
	            NSLog(@"Could not evaluate policy");
	            NSLog(@"%@",[authError localizedDescription]);
	            // Should pass string
	            @{FingerprintModule:Of(_this).AuthResult(bool, string):Call(false, [authError localizedDescription])};
	        }
		@}

		[Foreign(Language.ObjC)]
		public extern(iOS) void Stop() 
		@{
			
		@}

	}


	[Require("AndroidManifest.Permission", "android.permission.USE_FINGERPRINT")]
	[ForeignInclude(Language.Java, "android.app.KeyguardManager")]
	[ForeignInclude(Language.Java, "android.content.pm.PackageManager")]
	[ForeignInclude(Language.Java, "android.hardware.fingerprint.FingerprintManager")]
	[ForeignInclude(Language.Java, "android.Manifest")]
	[ForeignInclude(Language.Java, "android.os.Build")]
	[ForeignInclude(Language.Java, "android.os.Bundle")]
	[ForeignInclude(Language.Java, "android.security.keystore.KeyGenParameterSpec")]
	[ForeignInclude(Language.Java, "android.security.keystore.KeyPermanentlyInvalidatedException")]
	[ForeignInclude(Language.Java, "android.security.keystore.KeyProperties")]
	[ForeignInclude(Language.Java, "android.support.v7.app.AppCompatActivity")]
	[ForeignInclude(Language.Java, "android.support.v4.app.ActivityCompat")]
	[ForeignInclude(Language.Java, "java.io.IOException")]
	[ForeignInclude(Language.Java, "java.security.InvalidAlgorithmParameterException")]
	[ForeignInclude(Language.Java, "java.security.InvalidKeyException")]
	[ForeignInclude(Language.Java, "java.security.KeyStore")]
	[ForeignInclude(Language.Java, "java.security.KeyStoreException")]
	[ForeignInclude(Language.Java, "java.security.NoSuchAlgorithmException")]
	[ForeignInclude(Language.Java, "java.security.NoSuchProviderException")]
	[ForeignInclude(Language.Java, "java.security.UnrecoverableKeyException")]
	[ForeignInclude(Language.Java, "java.security.cert.CertificateException")]
	[ForeignInclude(Language.Java, "javax.crypto.Cipher")]
	[ForeignInclude(Language.Java, "javax.crypto.KeyGenerator")]
	[ForeignInclude(Language.Java, "javax.crypto.NoSuchPaddingException")]
	[ForeignInclude(Language.Java, "javax.crypto.NoSuchPaddingException")]
	[ForeignInclude(Language.Java, "javax.crypto.SecretKey")]
	[ForeignInclude(Language.Java, "com.fuse.Activity")]
	[ForeignInclude(Language.Java, "android.os.CancellationSignal")]	
	extern(Android) class FingerPrintImpl : IFingerPrint 
	{
		Java.Object _cancellationSignal;

		public void AuthResult(bool Result, string Msg) {
			FingerprintModule.AuthDone(Result, Msg);
		}

		[Foreign(Language.Java)]
		public extern(Android) bool IsSupported() 
		@{			
			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
				KeyguardManager keyguardManager = (KeyguardManager) Activity.getRootActivity().getSystemService(Activity.getRootActivity().KEYGUARD_SERVICE);
    			FingerprintManager fingerprintManager = (FingerprintManager) Activity.getRootActivity().getSystemService(Activity.getRootActivity().FINGERPRINT_SERVICE);
    			if (!fingerprintManager.isHardwareDetected()) {
    				return false;
    			}
    			if (ActivityCompat.checkSelfPermission(Activity.getRootActivity(), Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
    				return false;
    			}
    			if (!fingerprintManager.hasEnrolledFingerprints()) {
    				return false;
    			}
    			if (!keyguardManager.isKeyguardSecure()) {
    				return false;
    			}
    		}
    		return true;
		@}

		[Foreign(Language.Java)]
		public extern(Android) void Authenticate(string reason)
		@{
			if (@{FingerPrintImpl:Of(_this).IsSupported():Call()}) {
				try {
					FingerprintManager fingerprintManager = (FingerprintManager) Activity.getRootActivity().getSystemService(Activity.getRootActivity().FINGERPRINT_SERVICE);
					KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
					KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
				    //Initialize an empty KeyStore//
				    keyStore.load(null);

				    //Initialize the KeyGenerator//
				    keyGenerator.init(new
				    	//Specify the operation(s) this key can be used for//
					    KeyGenParameterSpec.Builder("KEY_NAME",
					    KeyProperties.PURPOSE_ENCRYPT |
					        KeyProperties.PURPOSE_DECRYPT)
					   .setBlockModes(KeyProperties.BLOCK_MODE_CBC)

					    //Configure this key so that the user has to confirm their identity with a fingerprint each time they want to use it//
					      .setUserAuthenticationRequired(true)
					      .setEncryptionPaddings(
					       KeyProperties.ENCRYPTION_PADDING_PKCS7)
				    .build());

				    //Generate the key//
				    keyGenerator.generateKey();
				    Cipher cipher = Cipher.getInstance(
				       KeyProperties.KEY_ALGORITHM_AES + "/"
				          + KeyProperties.BLOCK_MODE_CBC + "/"
				          + KeyProperties.ENCRYPTION_PADDING_PKCS7);
				    keyStore.load(null);
				    SecretKey key = (SecretKey) keyStore.getKey("KEY_NAME",
				          null);
				    cipher.init(Cipher.ENCRYPT_MODE, key);

				    FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);

				    CancellationSignal cancellationSignal = new CancellationSignal();
				    @{FingerPrintImpl:Of(_this)._cancellationSignal:Set(cancellationSignal)};
				    fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, new FingerprintManager.AuthenticationCallback() {
				    	
				    	@Override
						public void onAuthenticationError(int errMsgId, CharSequence errString) {							
						}

						@Override
						public void onAuthenticationFailed() {
							@{FingerPrintImpl:Of(_this).AuthResult(bool,string):Call(false, "Auth Failed")};
						}

						@Override
						public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {							
						}

						@Override
						public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
							@{FingerPrintImpl:Of(_this).AuthResult(bool,string):Call(true, "Auth Success")};
						}

				    }, null);
				} catch (Exception exc) {
					@{FingerPrintImpl:Of(_this).AuthResult(bool,string):Call(false, exc.getMessage())};
				}    			
			}else {
				@{FingerPrintImpl:Of(_this).AuthResult(bool,string):Call(false, "Fingerprint not supported")};
			}
		@}		

		[Foreign(Language.Java)]
		public extern(Android) void Stop() 
		@{
			CancellationSignal signal = (CancellationSignal)@{FingerPrintImpl:Of(_this)._cancellationSignal:Get()};
		    if (signal != null) {
		        signal.cancel();
		        signal = null;
		    }
		@}
	}

	class InvokeEnclosure {
		Fuse.Scripting.Function _callback;
		bool _callback_succ;
		string _callback_text;		
		
		public InvokeEnclosure ( Fuse.Scripting.Function func, bool cbsucc, string cbtext) {			
			_callback = func;
			_callback_succ = cbsucc;
			_callback_text = cbtext;			
		}
		public void InvokeCallback (Context _context) {
			_callback.Call(_context, _callback_succ, _callback_text);
		}
	}
}
