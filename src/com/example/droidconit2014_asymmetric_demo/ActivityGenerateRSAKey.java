package com.example.droidconit2014_asymmetric_demo;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.example.droidconit2014_asymmetric_demo_step_x1.R;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.Fragment;
import android.app.ProgressDialog;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class ActivityGenerateRSAKey extends Activity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_generatersakey);

		if (savedInstanceState == null) {
			getFragmentManager().beginTransaction()
					.add(R.id.container, new PlaceholderFragment()).commit();
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {

		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		switch (item.getItemId()) {
		case R.id.action_settings:
			return true;
		}
		return super.onOptionsItemSelected(item);
	}

	/*
	 * A placeholder fragment containing a simple view.
	 */
	public static class PlaceholderFragment extends Fragment implements
			View.OnClickListener {

		private Button exit_Button;
		private Button mGenChiaviButton;
		private Button viewParameterButton;
		private Button mCifraButton;
		private Button mDecifraButton;
		private TextView mDebugText;
		private EditText mInData;
		private EditText mOutData;
		ProgressDialog progressdialog;

		private static final String TAG = "ActivityGenerateRSAKey";

		public PlaceholderFragment() {
		}

		@Override
		public View onCreateView(LayoutInflater inflater, ViewGroup container,
				Bundle savedInstanceState) {
			View rootView = inflater.inflate(R.layout.fragment_generatersakey,
					container, false);

			// Bottoni
			exit_Button = (Button) rootView.findViewById(R.id.exit_button);
			exit_Button.setOnClickListener(this);
			mGenChiaviButton = (Button) rootView
					.findViewById(R.id.generate_button);
			mGenChiaviButton.setOnClickListener(this);

			viewParameterButton = (Button) rootView
					.findViewById(R.id.view_param_button);
			viewParameterButton.setOnClickListener(this);

			mCifraButton = (Button) rootView.findViewById(R.id.cifra_button);
			mCifraButton.setOnClickListener(this);
			mDecifraButton = (Button) rootView
					.findViewById(R.id.decifra_button);
			mDecifraButton.setOnClickListener(this);

			// Text View
			mInData = (EditText) rootView.findViewById(R.id.inDataText);
			mOutData = (EditText) rootView.findViewById(R.id.outDataText);
			mDebugText = (TextView) rootView.findViewById(R.id.debugText);

			return rootView;
		}

		@Override
		public void onClick(View view) {

			switch (view.getId()) {
			case R.id.exit_button:
				debug("Cliccato Chiudi");
				this.getActivity().finish();
				break;
			case R.id.generate_button:
				debug("Cliccato Genera chiavi");
				generaChiavi();
				break;
			case R.id.view_param_button:
				debug("Cliccato Visulizza Parametri");
				visulizzaModulo_EsponentePubblico_EsponentePrivato();
				break;

			case R.id.cifra_button:
				debug("Cliccato Cifra");
				cifraData();
				break;
			case R.id.decifra_button:
				debug("Cliccato Decifra");
				decifraData();
				break;

			}
		}

		Key publicKey = null;
		Key privateKey = null;
		KeyPair keypair = null;

		BigInteger m = null;
		BigInteger e = null;
		BigInteger d = null;
		
		byte[] cipheredData = null;
		byte[] decipheredData = null;

		private void generaChiavi() {
			//clearText();

			showProviders();
			// Restituisce un generatore di chiavi per RSA
			KeyPairGenerator kpg = null;
			try {
				kpg = KeyPairGenerator.getInstance("RSA");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}

			debug("Provider utilizzato : " + kpg.getProvider().getName());

			SecureRandom sr = null;
			try {
				sr = SecureRandom.getInstance("SHA1PRNG");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			// Inizilizza il generatore specificando la lunghezza della chiave
			kpg.initialize(2048, sr);

			// Restiruisce un KeyPair (contiene chiave pubblica/privata)
			keypair = kpg.genKeyPair();

			// Restituisce la chiave pubblica
			publicKey = keypair.getPublic();

			// Restituisce la chiave privata
			privateKey = keypair.getPrivate();
			
			

			visulizzaModulo_EsponentePubblico_EsponentePrivato();

		}


		private void cifraData() {

			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
			KeyFactory factory = null;
			try {
				factory = KeyFactory.getInstance("RSA");
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			PublicKey pubKey = null;
			try {
				pubKey = factory.generatePublic(keySpec);
			} catch (InvalidKeySpecException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

			Cipher cipher = null;
			try {
				cipher = Cipher.getInstance("RSA");
				
				//cipher = Cipher.getInstance("RSA/None/OAEPWithSHA-256AndMGF1Padding");
				//cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				
				
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchPaddingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			try {
				cipher.init(Cipher.ENCRYPT_MODE, pubKey);
				 //cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			} catch (InvalidKeyException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
			String plainText = mInData.getText().toString();
			try {
				cipheredData = cipher.doFinal(plainText.getBytes());
			} catch (IllegalBlockSizeException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (BadPaddingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
			String base64_cipheredData = Base64.encodeToString(
					cipheredData, Base64.DEFAULT);
			mOutData.setText(base64_cipheredData);

		}

		private void decifraData() {
			// TODO Auto-generated method stub
			RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, d);
			KeyFactory keyfactory = null;
			PrivateKey privKey = null;
			try {
				keyfactory = KeyFactory.getInstance("RSA");
			} catch (NoSuchAlgorithmException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			}

			try {
				privKey = keyfactory.generatePrivate(keySpec);
			} catch (InvalidKeySpecException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

			Cipher de_cipher = null;
			try {
				//de_cipher = Cipher.getInstance("RSA/None/OAEPWithSHA-256AndMGF1Padding");
				de_cipher = Cipher.getInstance("RSA");
				//de_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchPaddingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			try {
				de_cipher.init(Cipher.DECRYPT_MODE, privKey);
			} catch (InvalidKeyException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
			byte[] base64_cipheredData = mOutData.getText().toString().getBytes();
			byte[] cipheredData = Base64.decode(base64_cipheredData, Base64.DEFAULT);
			
			try {
				decipheredData = de_cipher.doFinal(cipheredData);
			} catch (IllegalBlockSizeException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (BadPaddingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
			String decipheredText = new String(decipheredData);
			mOutData.setText(decipheredText);
			debug("Testo decifrato: " + decipheredText);

		}

		
		
		
		private void showProviders() {
			Provider[] providers = Security.getProviders();
			for (Provider provider : providers) {
				debug("Provider: " + provider.getName());
				debug("Version : " + Double.toString(provider.getVersion()));
				// debug("Info    : " + provider.getInfo());
				Set<Provider.Service> services = provider.getServices();
				//if (provider.getName().equalsIgnoreCase("AndroidOpenSSL")) {
					for (Provider.Service service : services) {
						//if(service.getAlgorithm().equalsIgnoreCase("RSA"))
							debug("  algorithm: " + service.getAlgorithm());
							debug(service.toString());

					}
				//}
				debug("\n");
			}
		}

		private void visulizzaModulo_EsponentePubblico_EsponentePrivato() {
			clearText();
			// Manipola le chiavi passando da una rappresentazione all'altra
			KeyFactory factory = null;
			try {
				factory = KeyFactory.getInstance("RSA");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}

			RSAPublicKeySpec rsa_public_key = null;
			try {
				rsa_public_key = factory.getKeySpec(keypair.getPublic(),
						RSAPublicKeySpec.class);
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			RSAPrivateKeySpec rsa_private_key = null;
			try {
				rsa_private_key = factory.getKeySpec(keypair.getPrivate(),
						RSAPrivateKeySpec.class);
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			// modulo "m" ed esponente "e" pubblico
			debug("Parametri della chiave pubblica");
			debug("Modulo pubblico esadecimale: "
					+ rsa_public_key.getModulus().toString(16));
			debug("Esponente pubblico esadecimale: "
					+ rsa_public_key.getPublicExponent().toString(16));
			debug("\n\n\n");
			// esponente privato d = e elevato alla -1 mod fi(n)=(p-1)(q-1)
			debug("Parametri della chiave privata");
			debug("Modulo pubblico esadecimale: "
					+ rsa_private_key.getModulus().toString(16));
			debug("Esponente Privato esadecimale: "
					+ rsa_private_key.getPrivateExponent().toString(16));

			m = rsa_public_key.getModulus();
			e = rsa_public_key.getPublicExponent();
			d = rsa_private_key.getPrivateExponent();
			
		}

		@SuppressLint("NewApi")
		private void debug(String message) {
			mDebugText.append(message + "\n");
			Log.v(TAG, message);
		}

		private void clearText() {
			mDebugText.setText("");
		}
	}

}
