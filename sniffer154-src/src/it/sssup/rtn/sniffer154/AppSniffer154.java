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
package it.sssup.rtn.sniffer154;

import it.sssup.retis.retisusbaccessory.RetisAccessoryService;
import it.sssup.rtn.sniffer154.sniffing.ISnifferService;
import it.sssup.rtn.sniffer154.sniffing.SnifferAccessoryService;
import it.sssup.rtn.sniffer154.sniffing.SnifferBinder;
import it.sssup.rtn.sniffer154.sniffing.SnifferDeviceService;
import it.sssup.rtn.sniffer154.sniffing.TestSnifferService;
import it.sssup.rtn.sniffer154.storage.PacketContentProvider;
import it.sssup.rtn.sniffer154.storage.PacketTable;
import it.sssup.rtn.sniffer154.storage.SessionTable;

import java.math.BigInteger;

import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.hardware.usb.UsbAccessory;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.net.Uri;
import android.os.IBinder;
import android.preference.PreferenceManager;
import android.util.Log;
import android.widget.Toast;

/**
 * This class provides the main methods for controlling the application status.
 * 
 * @author Daniele Alessandrelli
 * 
 */
public class AppSniffer154 extends Application {

	private static final String TAG = AppSniffer154.class.getSimpleName();

	public static final String INTENT_NEW_PACKET = "it.sssup.rtn.sniffer154.NEW_PACKET";
	public static final String PREFS_FILTER = "filterPref";
	public static final String ACTION_SNIFFING_STATE_CHANGED = "it.sssup.rtn.sniffer154.ACTION_SNIFFING_STATE_CHANGED";

	private ISnifferService mRealSniffer;
	private ISnifferService mTestSniffer;
	private ISnifferService mCurrentSniffer;
	private Uri sessionUri = Uri.EMPTY;
	private boolean testMode = false;
	private PacketForwarder mPacketForwarder;
	private boolean mSniffing = false;
	private final ServiceConnection mSnifferConnection = new SnifferConnection();
	private final ServiceConnection mTestConnection = new SnifferConnection();

	private long sessionTime;

	private BroadcastReceiver mSnifferReceiver = new SnifferReceiver();

	/*------------------------------------------------------------------------*/
	/* Application methods */
	/*------------------------------------------------------------------------*/

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.app.Application#onCreate()
	 */
	@Override
	public void onCreate() {
		super.onCreate();

		/* Disable filtering */
		SharedPreferences prefs = getSharedPreferences(PREFS_FILTER, 0);
		Editor prefsEditor = prefs.edit();
		prefsEditor.putBoolean(getString(R.string.prefsFilterEnableKey), false);
		prefsEditor.apply();
		mPacketForwarder = new PacketForwarder(this);
		displaySupportedUsbModes(this);
	}

	private static void displaySupportedUsbModes(Context context) {
		PackageManager pm;
		String s, accessorySupport, deviceSupport; 

		accessorySupport = deviceSupport = "NOT supported";
		pm = context.getPackageManager();
		if (pm.hasSystemFeature(PackageManager.FEATURE_USB_ACCESSORY)) {
			try {
				Class.forName(UsbAccessory.class.getName());
				Class.forName(UsbManager.class.getName());
				accessorySupport = "SUPPORTED";
			} catch (ClassNotFoundException e) {
				// do nothing
			}
		}
		if (pm.hasSystemFeature(PackageManager.FEATURE_USB_HOST)) {
			try {
				Class.forName(UsbDevice.class.getName());
				Class.forName(UsbManager.class.getName());
				deviceSupport = "SUPPORTED";
			} catch (ClassNotFoundException e) {
				// do nothing
			}
		}
		s = "USB accessory mode: " + accessorySupport + "\n";
		s += "USB host mode: " + deviceSupport;
		Toast.makeText(context, s, Toast.LENGTH_LONG).show();
	}

	/*------------------------------------------------------------------------*/
	/* Other methods */
	/*------------------------------------------------------------------------*/

	/**
	 * Creates a new sniffing session in the database
	 * 
	 * @return the URI of the new mSniffing session
	 */
	public Uri createNewSession() {
		ContentValues values;
		boolean forwarding;
		SharedPreferences prefs;

		values = new ContentValues();
		values.put(SessionTable.C_SESSION_DATE, System.currentTimeMillis());
		sessionUri = getContentResolver().insert(
				PacketContentProvider.SESSIONS_URI, values);
		updateSessionTime();
		// enable packet forwarding if required
		prefs = PreferenceManager.getDefaultSharedPreferences(this);
		forwarding = prefs.getBoolean(
				getString(R.string.prefsForwardingEnableKey), false);
		if (forwarding)
			mPacketForwarder.activate(sessionUri);

		return sessionUri;
	}

	/**
	 * 
	 * Deletes the sniffing session having the specified id
	 * 
	 * @param id
	 *            The ID of the mSniffing session to delete
	 * @return the number of sessions deleted
	 */
	public int deleteSession(long id) {
		Uri uri = ContentUris.withAppendedId(
				PacketContentProvider.SESSIONS_URI, id);
		return getContentResolver().delete(uri, null, null);
	}

	/**
	 * Adds a new packet to the database
	 * 
	 * @param sessionUri
	 *            the URI of the mSniffing session the packet belongs to
	 * @param packet
	 *            the packet's payload
	 */
	public void addPacket(Uri sessionUri, byte[] packet, byte[] crc,
			boolean crc_ok) {
		ContentValues values = new ContentValues();
		values.put(PacketTable.C_PACKET_DATE, System.currentTimeMillis()
				- sessionTime);
		values.put(PacketTable.C_PACKET_PAYLOAD, packet);
		values.put(PacketTable.C_PACKET_CRC, crc);
		values.put(PacketTable.C_PACKET_CRC_OK, crc_ok ? 1 : 0);
		Uri uri = Uri.withAppendedPath(sessionUri,
				PacketContentProvider.BASE_PATH_PACKETS);
		// Log.d("AppSniffer", uri.toString());
		getContentResolver().insert(uri, values);
	}

	/**
	 * Adds a new packet to the database
	 * 
	 * @param sessionUri
	 *            the URI of the mSniffing session the packet belongs to
	 * @param packet
	 *            the packet's payload
	 */
	public void addPacket(Uri sessionUri, byte[] packet, byte[] crc,
			boolean crc_ok, byte rssi, byte lqi) {
		ContentValues values = new ContentValues();
		values.put(PacketTable.C_PACKET_DATE, System.currentTimeMillis()
				- sessionTime);
		values.put(PacketTable.C_PACKET_PAYLOAD, packet);
		values.put(PacketTable.C_PACKET_CRC, crc);
		values.put(PacketTable.C_PACKET_CRC_OK, crc_ok ? 1 : 0);
		values.put(PacketTable.C_PACKET_RSSI, rssi);
		values.put(PacketTable.C_PACKET_RSSI, lqi);
		Uri uri = Uri.withAppendedPath(sessionUri,
				PacketContentProvider.BASE_PATH_PACKETS);
		// Log.d("AppSniffer", uri.toString());
		getContentResolver().insert(uri, values);
	}

	/**
	 * Checks whether it is possible to start sniffing or not
	 * 
	 * @return true if it is possible to start sniffing
	 */
	public boolean isSniffingEnabled() {
		Log.d(TAG, "is null? " + (mCurrentSniffer == null));
		return mCurrentSniffer != null;
	}

	/**
	 * Checks whether a sniffing session is in progress or not
	 * 
	 * @return true if a sniffing session is in progress
	 */
	public boolean isSniffingInProgress() {
		return mSniffing;
	}

	/**
	 * Checks whether test mode is enabled or not
	 * 
	 * @return true if test mode is enabled
	 */
	public boolean isTestModeEnblad() {
		return testMode;
	}

	/**
	 * Toggles test mode
	 */
	public void toggleTestMode() {
		// stop mSniffing if it were running
		if (mSniffing)
			stopSniffing(this);
		testMode = !testMode;
		if (testMode) {
			// set mCurrentSniffer to null
			// it will be set to mTestSniffer after the binding
			mCurrentSniffer = null;
			startTestService();
		} else {
			mCurrentSniffer = mRealSniffer;
			stopTestService();
		}
	}

	/**
	 * Starts sniffing
	 * 
	 * @param context
	 *            - the context of the component requesting to start sniffing
	 */
	public void startSniffing(Context context) {
		byte channel;
		SharedPreferences prefs;

		prefs = PreferenceManager.getDefaultSharedPreferences(this);
		channel = (byte) prefs.getInt(
				getString(R.string.prefsSniffingChannelKey), 0);
		mSniffing = mCurrentSniffer.startSniffing(channel);
		if (!mSniffing)
			Toast.makeText(this, "Failed to start sniffing :(",
					Toast.LENGTH_LONG).show();
		notifySniffingStateChanged();
	}

	/**
	 * Stops sniffing
	 * 
	 * @param context
	 *            - the context of the component requesting to stop sniffing
	 */
	public void stopSniffing(Context context) {
		if (mCurrentSniffer != null) {
			mSniffing = !mCurrentSniffer.stopSniffing();
			if (!mSniffing)
				mPacketForwarder.deactivate();
		} else {
			mSniffing = false;
		}
		notifySniffingStateChanged();
	}

	/**
	 * Starts the test service
	 */
	private void startTestService() {
		Intent service;

		service = new Intent(this, TestSnifferService.class);
		bindService(service, mTestConnection, Context.BIND_AUTO_CREATE);
	}

	/**
	 * Stops the test service
	 */
	private void stopTestService() {
		unbindService(mTestConnection);
	}

	private void snifferDeviceAttached() {
		Log.d(TAG, "snifferDeviceAttached()");
		IntentFilter filter;
		Intent service;

		filter = new IntentFilter(UsbManager.ACTION_USB_DEVICE_DETACHED);
		registerReceiver(mSnifferReceiver, filter);
		service = new Intent(this, SnifferDeviceService.class);
		bindService(service, mSnifferConnection, Context.BIND_AUTO_CREATE);
		Toast.makeText(this, "Sniffer attached!", Toast.LENGTH_SHORT).show();
	}

	/**
	 * Handles the sniffer attachment event
	 */
	private void snifferAccessoryAttached() {
		Log.d(TAG, "snifferAttached()");
		IntentFilter filter;
		Intent service;

		filter = new IntentFilter(UsbManager.ACTION_USB_ACCESSORY_DETACHED);
		registerReceiver(mSnifferReceiver, filter);
		service = new Intent(this, SnifferAccessoryService.class);
		bindService(service, mSnifferConnection, Context.BIND_AUTO_CREATE);
		Toast.makeText(this, "Sniffer attached!", Toast.LENGTH_SHORT).show();
	}

	/**
	 * Handles the sniffer detachment event
	 */
	private void snifferDetached() {
		mRealSniffer = null;
		unregisterReceiver(mSnifferReceiver);
		if (!testMode) {
			mCurrentSniffer = null;
			mSniffing = false;
		}
		notifySniffingStateChanged();
		if (mSnifferConnection != null)
			unbindService(mSnifferConnection);
	}

	/**
	 * Sets the URI of the current sniffing session, i.e., the session that is
	 * displayed by the {@link PacketListActivity}
	 * 
	 * @param uri
	 *            - the uri of the current session
	 */
	public void setSessionUri(Uri uri) {
		sessionUri = uri;
		updateSessionTime();
	}

	/**
	 * Returns the URI of the current sniffing session
	 * 
	 * @return
	 */
	public Uri getSessionUri() {
		return sessionUri;
	}

	/**
	 * Converts a byte array to an hex string
	 * 
	 * @param bytes
	 *            the byte array to be converted
	 * @return the string containing the hex representation of the input byte
	 *         array
	 */
	public static String toHexString(byte[] bytes) {
		BigInteger bi = new BigInteger(1, bytes);
		String retv = String.format("%0" + (bytes.length << 1) + "X", bi);
		return retv;
	}

	/**
	 * Updates the session time
	 */
	private void updateSessionTime() {
		Cursor cur = getContentResolver().query(sessionUri, null, null, null,
				null);
		cur.moveToFirst();
		sessionTime = cur.getLong(cur
				.getColumnIndex(SessionTable.C_SESSION_DATE));
		cur.close();
	}

	/**
	 * Notifies other components that the sniffing state (e.g., sniffing
	 * enabled/disabled, sniffing in progress, etc.) is changed.
	 */
	private void notifySniffingStateChanged() {
		Intent intent;

		intent = new Intent(ACTION_SNIFFING_STATE_CHANGED);
		sendBroadcast(intent);
	}

	/**
	 * Class to handle the connection with the SnifferService
	 * 
	 * @author Daniele Alessandrelli
	 * 
	 */
	private class SnifferConnection implements ServiceConnection {

		@Override
		public void onServiceDisconnected(ComponentName name) {
			if (name.getClassName().equals(
					SnifferAccessoryService.class.getName())) {
				mRealSniffer = null;
			}
			if (name.getClassName()
					.equals(SnifferDeviceService.class.getName())) {
				mRealSniffer = null;
			}
			if (name.getClassName().equals(TestSnifferService.class.getName())) {
				mTestSniffer = null;
			}
			if (testMode)
				mCurrentSniffer = mTestSniffer;
			else
				mCurrentSniffer = mRealSniffer;
			notifySniffingStateChanged();
		}

		@Override
		public void onServiceConnected(ComponentName name, IBinder service) {
			SnifferBinder binder;
			Log.d(TAG, "onServiceConnected()");

			binder = (SnifferBinder) service;

			if (name.getClassName().equals(
					SnifferAccessoryService.class.getName())) {
				mRealSniffer = binder.getService();
			}
			if (name.getClassName()
					.equals(SnifferDeviceService.class.getName())) {
				mRealSniffer = binder.getService();
			}
			if (name.getClassName().equals(TestSnifferService.class.getName())) {
				mTestSniffer = binder.getService();
			}
			if (testMode)
				mCurrentSniffer = mTestSniffer;
			else
				mCurrentSniffer = mRealSniffer;
			notifySniffingStateChanged();
		}
	};

	/**
	 * Class to receive notification of accessory detachment
	 * 
	 * @author Daniele Alessandrelli
	 * 
	 */
	private class SnifferReceiver extends BroadcastReceiver {

		@Override
		public void onReceive(Context context, Intent intent) {

			if (intent.getAction().equals(
					UsbManager.ACTION_USB_ACCESSORY_DETACHED)) {
				Toast.makeText(context, "Sniffer detached!", Toast.LENGTH_SHORT)
						.show();
				snifferDetached();
			} else if (intent.getAction().equals(
					UsbManager.ACTION_USB_DEVICE_DETACHED)) {
				Toast.makeText(context, "Sniffer device detached!",
						Toast.LENGTH_SHORT).show();
				snifferDetached();
			}
		}
	}

	public void checkForSnifferAttachedAction(Intent intent) {
		if (RetisAccessoryService.isActionUsbAccessoryAttached(this, intent)) {
			snifferAccessoryAttached();
		}
		if (SnifferDeviceService.isUsbDeviceAttachedAction(this, intent)) {
			snifferDeviceAttached();
		}
	}

}
