/*
 * Copyright (C) 2012,2013 Scuola Superiore Sant'Anna (http://www.sssup.it) 
 * and Consorzio Nazionale Interuniversitario per le Telecomunicazioni 
 * (http://www.cnit.it).
 * 
 * This file is part of Sniffer 15.4, an IEEE 802.15.4 packet sniffer for 
 * Android devices.
 * 
 * Sniffer 15.4 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *  
 * Sniffer 15.4 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with Sniffer 15.4.  If not, see <http://www.gnu.org/licenses/>.
 */
package it.sssup.rtn.sniffer154.sniffing;

import it.sssup.rtn.sniffer154.AppSniffer154;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.hardware.usb.UsbManager;
import android.net.Uri;
import android.os.IBinder;
import android.util.Log;
import android.widget.Toast;

import com.hoho.android.usbserial.driver.UsbSerialDriver;
import com.hoho.android.usbserial.driver.UsbSerialProber;
import com.hoho.android.usbserial.util.SerialInputOutputManager;

public class SnifferDeviceService extends Service implements ISnifferService {

	private static final String TAG = SnifferDeviceService.class
			.getSimpleName();
	private static final byte[] magic = { 'S', 'N', 'I', 'F' };

	@SuppressWarnings("unused")
	private static final byte FIELD_TIMESTAMP = 16;
	private static final byte[] PKT_STOP_SNIF = { (byte) 0xFB, '\n' };
	private static final byte[] PKT_START_SNIF = { (byte) 0xFA, 0, '\n' };
	private static final byte SERIAL_CHANNEL_OFFSET = 0x20;

	private final ExecutorService mExecutor = Executors
			.newSingleThreadExecutor();
	private final IBinder mBinder = new SnifferBinder(this);

	private Uri mSessionUri;
	private SerialInputOutputManager mSerialIoManager;
	private UsbManager mUsbManager;
	private UsbSerialDriver mSerialDevice;
	private PipedOutputStream mPipedOut;
	private PipedInputStream mPipedIn;

	private Runnable mSnifferReader = new Runnable() {

		@Override
		public void run() {
			Log.d(TAG, "mSnifferReader::run()");
			try {
				while (true) {
					SnifferUtils.sync(mPipedIn, magic);
					SnifferUtils.parseInPkt(mPipedIn, mSessionUri,
							(AppSniffer154) getApplication());
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	};

	private final SerialInputOutputManager.Listener mListener = new SerialInputOutputManager.Listener() {

		@Override
		public void onRunError(Exception e) {
			// FIXME: check if we must do something here
			Log.d(TAG, "Runner stopped.");
		}

		@Override
		public void onNewData(final byte[] data) {
			try {
				mPipedOut.write(data);
				// mPipedOut.flush();
			} catch (IOException e) {
				Log.e(TAG, "mListener.onNewData()", e);
			}
		}
	};

	@Override
	public boolean startSniffing(byte channelId) {
		AppSniffer154 app;
		app = (AppSniffer154) getApplication();
		mSessionUri = app.createNewSession();
		// write sniffing channel
		PKT_START_SNIF[1] = (byte) (channelId + SERIAL_CHANNEL_OFFSET);
		mSerialIoManager.writeAsync(PKT_START_SNIF);
		return true;
	}

	@Override
	public boolean stopSniffing() {
		mSerialIoManager.writeAsync(PKT_STOP_SNIF);
		mSessionUri = null;
		return true;
	}

	@Override
	public void onCreate() {
		Log.d(TAG, "onCreate()");
		super.onCreate();
		mPipedOut = new PipedOutputStream();
		try {
			mPipedIn = new PipedInputStream(mPipedOut, 1024);
		} catch (IOException e) {
			// we should never get here
			e.printStackTrace();
		}
		Thread th = new Thread(mSnifferReader);
		th.start();
		setupUsbDevice();
	}

	@Override
	public void onDestroy() {
		if (mSerialIoManager != null) {
			mSerialIoManager.writeAsync(PKT_STOP_SNIF);
			Log.i(TAG, "Stopping io manager ..");
			mSerialIoManager.stop();
			mSerialIoManager = null;
		}
		super.onDestroy();
	}

	private void setupUsbDevice() {
		mUsbManager = (UsbManager) getSystemService(Context.USB_SERVICE);
		mSerialDevice = UsbSerialProber.acquire(mUsbManager);
		if (mSerialDevice == null) {
			Toast.makeText(this, "Cannot find USB device", Toast.LENGTH_SHORT)
					.show();
		} else {
			try {
				mSerialDevice.open();
			} catch (IOException e) {
				Log.e(TAG, "Error setting up device: " + e.getMessage(), e);
				try {
					mSerialDevice.close();
				} catch (IOException e2) {
					// Ignore.
				}
				mSerialDevice = null;
				return;
			}
		}
		mSerialIoManager = new SerialInputOutputManager(mSerialDevice,
				mListener);
		mExecutor.submit(mSerialIoManager);
	}

	@Override
	public boolean onUnbind(Intent intent) {
		Log.d(TAG, "onUnbind()");
		return super.onUnbind(intent);
	}

	@Override
	public IBinder onBind(Intent intent) {
		return mBinder;
	}

	public static boolean isUsbDeviceAttachedAction(Context context,
			Intent intent) {
		boolean retv;

		retv = false;
		try {
			retv = (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(intent
					.getAction()));
		} catch (NoClassDefFoundError e) {
			Toast.makeText(
					context,
					"Warning: your device does not support the Android USB "
							+ "device/accessory feature", Toast.LENGTH_LONG)
					.show();
		}
		return retv;
	}

}
