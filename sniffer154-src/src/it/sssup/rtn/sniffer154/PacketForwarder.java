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
 
import it.sssup.rtn.sniffer154.storage.PacketContentProvider;
import it.sssup.rtn.sniffer154.storage.PacketTable;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.Arrays;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Handler;
import android.preference.PreferenceManager;
import android.util.Log;
import android.widget.Toast;

/**
 * A class for forwarding captured frames to an arbitrary IP address. The class
 * implements a ContantObserver to be notified when a new frame is captured. The
 * class extends an OnSharedPreferenceChangeListener to be notified when the
 * destination IP address/port changes.
 * 
 * @author Daniele Alessandrelli
 */

public class PacketForwarder extends ContentObserver implements
		OnSharedPreferenceChangeListener {

	private static final String TAG = PacketForwarder.class.getSimpleName();
	private static final int ZEP_V1_HEADER_LENGTH = 16;
	private static final int ZEP_V2_HEADER_LENGTH = 32;
	private static final byte LQI_MODE = 0;
	private static final byte CRC_MODE = 1;

	private String mAddr;
	private int mPort;
	private Context mContext;
	private Uri mUri;

	private boolean mForwardEnabled;

	private DatagramSocket mSocket;

	/**
	 * The constructor
	 * 
	 * @param context
	 *            The context
	 */
	public PacketForwarder(Context context) {
		super(new Handler());
		mContext = context;
	}

	/**
	 * Activates this PacketForwarder
	 * 
	 * @param sessionUri
	 *            The URI of the session to be forwarded
	 * @return true if the activation was successful
	 */
	public boolean activate(Uri sessionUri) {
		try {
			mSocket = new DatagramSocket();
		} catch (SocketException e) {
			Log.e(TAG, "Failed to open forwarding socket", e);
			return false;
		}
		mUri = Uri.withAppendedPath(sessionUri,
				PacketContentProvider.BASE_PATH_PACKETS);
		mContext.getContentResolver().registerContentObserver(mUri, true, this);
		SharedPreferences sharedPreferences = PreferenceManager
				.getDefaultSharedPreferences(mContext);
		sharedPreferences.registerOnSharedPreferenceChangeListener(this);
		updatePrefs();

		return true;
	}

	/**
	 * Deactivate this PacketForwarder
	 */
	public synchronized void deactivate() {
		mContext.getContentResolver().unregisterContentObserver(this);
		PreferenceManager.getDefaultSharedPreferences(mContext)
				.unregisterOnSharedPreferenceChangeListener(this);
		if (mSocket != null)
			mSocket.close();
		mSocket = null;
	}

	/**
	 * Checks if the forwarding settings are changed and updates this
	 * PacketForwarder
	 */
	private void updatePrefs() {
		SharedPreferences prefs;
		Editor editor;

		prefs = PreferenceManager.getDefaultSharedPreferences(mContext);
		mForwardEnabled = prefs.getBoolean(
				mContext.getString(R.string.prefsForwardingEnableKey), false);
		if (mForwardEnabled) {
			try {
				mAddr = prefs.getString(
						mContext.getString(R.string.prefsForwardingAddressKey),
						"");
				mPort = Integer.parseInt(prefs.getString(
						mContext.getString(R.string.prefsForwardingPortKey),
						"17754"));
				if (mPort < 1 || mPort > 65535)
					throw new NumberFormatException("Invalid port number: "
							+ mPort);
			} catch (NumberFormatException e) {
				Toast.makeText(mContext,
						"Incorrect forwarding port. Forwarding disabled!",
						Toast.LENGTH_LONG).show();
				mForwardEnabled = false;
				editor = prefs.edit();
				editor.putBoolean(
						mContext.getString(R.string.prefsForwardingEnableKey),
						false);
				editor.commit();
			}
		}
	}

	/**
	 * Forwards the last captured frame
	 * 
	 * @throws IOException
	 *             If the forwarding fails
	 */
	private synchronized void forwardLastPacket() throws IOException {
		byte[] pkt;
		byte[] crc;
		boolean crc_ok;
		int rssi;
		int lqi;
		int chan;
		long time_ms;
		byte[] zep_pkt;
		DatagramPacket p;
		Cursor cur;
		InetSocketAddress addr;

		chan = 0; // FIXME: use the right channel
		cur = mContext.getContentResolver().query(mUri, null, null, null,
				PacketTable.C_PACKET_DATE + " DESC");
		cur.moveToFirst();
		if (cur.getCount() == 0)
			return;
		pkt = cur.getBlob(cur.getColumnIndex(PacketTable.C_PACKET_PAYLOAD));
		crc = cur.getBlob(cur.getColumnIndex(PacketTable.C_PACKET_CRC));
		crc_ok = cur.getInt(cur.getColumnIndex(PacketTable.C_PACKET_CRC_OK)) == 1 ? true
				: false;
		rssi = cur.getInt(cur.getColumnIndex(PacketTable.C_PACKET_RSSI));
		lqi = cur.getInt(cur.getColumnIndex(PacketTable.C_PACKET_LQI));
		time_ms = cur.getLong(cur.getColumnIndex(PacketTable.C_PACKET_DATE));
		cur.close();
		zep_pkt = createZepPacketv2(time_ms, chan, pkt, crc, crc_ok, rssi, lqi);
		addr = new InetSocketAddress(mAddr, mPort);
		p = new DatagramPacket(zep_pkt, zep_pkt.length, addr);
		if (mSocket != null)
			mSocket.send(p);
		// Log.d(TAG, "forwardLastPacket()");
	}

	/**
	 * Create a ZEPv1 packet encapsulating the IEEE 802.15.4 frame
	 * 
	 * @param pkt
	 *            - the IEEE 802.15.4 frame to be encapsulated
	 * @param channel
	 *            - the sniffing channel
	 * @param lqi
	 *            - the frame LQI
	 * @return the ZEPv1 packet
	 */
	@SuppressWarnings("unused")
	private static byte[] createZepPacket(byte[] pkt, int channel, int lqi) {
		byte[] retv = new byte[pkt.length + ZEP_V1_HEADER_LENGTH];
		/* Preamble */
		retv[0] = 'E';
		retv[1] = 'X';
		/* Vesion */
		retv[2] = 0x01;
		/* Channel */
		retv[3] = (byte) channel;
		/* Device ID (sniffer ID) */
		retv[4] = (byte) 0xAB;
		retv[5] = (byte) 0xCD;
		/* CRC/LQI Mode */
		retv[6] = 0x00;
		/* LQI value */
		retv[7] = (byte) lqi;
		/* Reserved */
		retv[8] = 0x00;
		retv[9] = 0x00;
		retv[10] = 0x00;
		retv[11] = 0x00;
		retv[12] = 0x00;
		retv[13] = 0x00;
		retv[14] = 0x00;
		/* Length */
		retv[15] = (byte) (pkt.length);
		/* 802.15.4 packet */
		for (int i = 0; i < pkt.length; i++) {
			retv[i + ZEP_V1_HEADER_LENGTH] = pkt[i];
		}
		return retv;
	}

	/**
	 * Create a ZEPv2 packet encapsulating the IEEE 802.15.4 frame
	 * 
	 * @param time_ms
	 *            - the frame timestamp
	 * @param channel
	 *            - the sniffing channel
	 * @param pkt
	 *            - the IEEE 802.15.4 frame to be encapsulated (w/o CRC)
	 * @param crc
	 *            - the CRC of the IEEE 802.15.4 frame
	 * @param crc_ok
	 *            - whether the CRC is okay or not
	 * @param rssi
	 *            - the RSSI of the frame
	 * @param lqi
	 *            - the frame LQI
	 * @return the ZEPv2 packet
	 */
	private static byte[] createZepPacketv2(long time_ms, int channel,
			byte[] pkt, byte[] crc, boolean crc_ok, int rssi, int lqi) {
		byte[] retv;
		long sec;
		long ms;

		// we add two bytes to store the crc or the rssi and lqi values
		// (CC2420 txfifo format)
		retv = new byte[pkt.length + ZEP_V2_HEADER_LENGTH + 2];
		/* Preamble */
		retv[0] = 'E';
		retv[1] = 'X';
		/* Vesion */
		retv[2] = 0x02;
		/* Type */
		retv[3] = 0x01;
		/* Channel */
		retv[4] = (byte) channel;
		/* Device ID (sniffer ID) */
		retv[5] = (byte) 0xAB;
		retv[6] = (byte) 0xCD;
		/* CRC/LQI Mode */
		retv[7] = (crc == null) ? LQI_MODE : CRC_MODE;
		/* LQI value */
		retv[8] = (byte) lqi;
		/* ntp_timestamp */
		sec = time_ms / 1000;
		retv[9] = (byte) ((sec >> 24) & 0xFF);
		retv[10] = (byte) ((sec >> 16) & 0xFF);
		retv[11] = (byte) ((sec >> 8) & 0xFF);
		retv[12] = (byte) ((sec >> 0) & 0xFF);
		ms = (long) ((time_ms % 1000) * 4294967.296);
		retv[13] = (byte) ((ms >> 24) & 0xFF);
		retv[14] = (byte) ((ms >> 16) & 0xFF);
		retv[15] = (byte) ((ms >> 8) & 0xFF);
		retv[16] = (byte) ((ms >> 0) & 0xFF);
		/* Sequence number */
		retv[17] = (0) >> 24;
		retv[18] = (0 >> 16) & 0xFF;
		retv[19] = (0 >> 8) & 0xFF;
		retv[20] = 0 & 0xFF;
		/* Reserved */
		Arrays.fill(retv, 21, 30, (byte) 0);
		/* Len */
		// we add two bytes to account for the crc or the LQI and RSSI values
		retv[31] = (byte) (pkt.length + 2);

		/* 802.15.4 packet */
		for (int i = 0; i < pkt.length; i++) {
			retv[i + ZEP_V2_HEADER_LENGTH] = pkt[i];
		}
		if (crc != null) {
			retv[ZEP_V2_HEADER_LENGTH + pkt.length] = crc[0];
			retv[ZEP_V2_HEADER_LENGTH + pkt.length + 1] = crc[1];
		} else {
			retv[ZEP_V2_HEADER_LENGTH + pkt.length] = (byte) (rssi & 0xFF);
			retv[ZEP_V2_HEADER_LENGTH + pkt.length + 1] = (byte) ((crc_ok) ? ((lqi & 0x7F) | 0x80)
					: lqi & 0x7F);
		}
		return retv;
	}

	/*-----------------------------------------------------------------------*/
	/* ContentObserver Implementation */
	/*-----------------------------------------------------------------------*/

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.database.ContentObserver#onChange(boolean)
	 */
	@Override
	public void onChange(boolean selfChange) {
		super.onChange(selfChange);
		// Log.d(TAG, "onChange()");
		if (mForwardEnabled == false)
			return;
		AsyncTask<String, Void, Void> task = new AsyncTask<String, Void, Void>() {

			@Override
			protected Void doInBackground(String... params) {
				try {
					forwardLastPacket();
				} catch (IOException e) {
					Log.w(TAG, e.getLocalizedMessage());
					//deactivate();
					//Log.e("PacketForwarder", "calling forwardLastPacket()", e);
				} catch (IllegalArgumentException e) {
					Log.w(TAG, e.getLocalizedMessage());
					// Log.e("PacketForwarder", "calling forwardLastPacket()",
					// e);
				}
				return null;
			}
		};
		task.execute("");
	}

	/*-----------------------------------------------------------------------*/
	/* ContentObserver Implementation */
	/*-----------------------------------------------------------------------*/

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.content.SharedPreferences.OnSharedPreferenceChangeListener#
	 * onSharedPreferenceChanged(android.content.SharedPreferences,
	 * java.lang.String)
	 */
	@Override
	public void onSharedPreferenceChanged(SharedPreferences sharedPreferences,
			String key) {
		updatePrefs();
	}
}
