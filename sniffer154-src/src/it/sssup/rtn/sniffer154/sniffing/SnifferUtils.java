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
import java.io.InputStream;
import java.util.Arrays;

import android.net.Uri;
import android.util.Log;

public class SnifferUtils {
	private static final String TAG = SnifferUtils.class.getSimpleName();
	
	private static final byte FIELD_CRC = 1;
	private static final byte FIELD_CRC_OK = 2;
	private static final byte FIELD_RSSI = 4;
	private static final byte FIELD_LQI = 8;

	public static void parseInPkt(InputStream in, Uri sessionUri, AppSniffer154 app) throws IOException {
		int tmp;
		byte type, rssi = 0, lqi = 0;
		byte[] pkt, crc = null;
		boolean crc_ok = true;

		// type
		//Log.d(TAG, "Getting type");
		tmp = in.read();
		if (tmp == -1)
			return;
		type = (byte) tmp;
		// len
		//Log.d(TAG, "Getting len");
		tmp = in.read();
		if (tmp == -1)
			return;
		// get 802.15.4 mpu
		pkt = new byte[tmp];
		//Log.d(TAG, "Getting packet");
		for (int i = 0; i < pkt.length; i++) {
			tmp = in.read();
			if (tmp == -1)
				return;
			pkt[i] = (byte) tmp;
		}
		// get CRC
		if ((type & FIELD_CRC) != 0) {
			//Log.d(TAG, "Getting CRC");
			crc = new byte[2];
			tmp = in.read();
			if (tmp == -1)
				return;
			crc[0] = (byte) tmp;
			tmp = in.read();
			if (tmp == -1)
				return;
			crc[1] = (byte) tmp;
			crc_ok = Arrays.equals(crc, computeFCS(pkt));
		}
		// get CRC_OK
		if ((type & FIELD_CRC_OK) != 0) {
			//Log.d(TAG, "Getting CRC_OK");
			tmp = in.read();
			if (tmp == -1)
				return;
			crc_ok = tmp == 0 ? false : true;
		}
		// get RSSI
		if ((type & FIELD_RSSI) != 0) {
			//Log.d(TAG, "Getting RSSI");
			tmp = in.read();
			if (tmp == -1)
				return;
			rssi = (byte) tmp;
		}
		// get LQI
		if ((type & FIELD_LQI) != 0) {
			//Log.d(TAG, "Getting LQI");
			tmp = in.read();
			if (tmp == -1)
				return;
			lqi = (byte) tmp;
		}
		if (sessionUri != null)
			app.addPacket(sessionUri, pkt, crc, crc_ok, rssi, lqi);
	}

	public static void sync(InputStream in, byte[] magic) throws IOException {
		//Log.d(TAG, "sync()");
		byte b;
		int idx = 0;
		int tmp;

		tmp = in.read();
		while (tmp != -1) {
			//Log.d(TAG, "sync(): b = " + Integer.toHexString(tmp) + " " + ((char) tmp));
			b = (byte) tmp;
			if (b == magic[idx]) {
				//Log.d(TAG, "sync(): step");
				idx++;
			} else {
				Log.d(TAG, "sync(): out of sync, restarting");
				idx = 0;
			}
			if (idx == magic.length) {
				//Log.d(TAG, "sync(): done");
				return;
			}
			tmp = in.read();
		}
	}
	
	public static byte[] computeFCS(byte[] packet) {
		int acc;
		byte[] retv = new byte[2];

		acc = 0;
		for (byte b : packet) {
			acc = crc16_add(b, acc);
		}
		retv[0] = (byte) (acc & 0xFF);
		retv[1] = (byte) ((acc >> 8) & 0xFF);

		return retv;
	}

	private static int crc16_add(byte b, int acc) {
		acc ^= (b & 0xFF);
		acc &= 0xFFFF;
		acc = (acc >> 8) | (acc << 8);
		acc &= 0xFFFF;
		acc ^= (acc & 0xff00) << 4;
		acc &= 0xFFFF;
		acc ^= (acc >> 8) >> 4;
		acc &= 0xFFFF;
		acc ^= (acc & 0xff00) >> 5;
		acc &= 0xFFFF;
		return acc;
	}
}
