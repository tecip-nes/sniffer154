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
import android.app.Service;
import android.content.Intent;
import android.net.Uri;
import android.os.Handler;
import android.os.IBinder;

/**
 * A service for simulating a sniffer accessory. This service is used to test
 * the application.
 * 
 * @author Daniele Alessandrelli
 * 
 */
public class TestSnifferService extends Service implements ISnifferService {

	@SuppressWarnings("unused")
	private static final String TAG = TestSnifferService.class.getSimpleName();
	private final static long PERIOD = 1000;
	private long count = 0;
	private Uri sessionUri;

	@SuppressWarnings("unused")
	private final static String TYPE_SELECTION = "substr(hex(substr(payload,1,1)),2,1)&7=?";
	private final IBinder mBinder = new SnifferBinder(this);

	private final Handler mHandler = new Handler();

	private Runnable periodicTask = new Runnable() {
		@Override
		public void run() {
			byte[] packet;
			byte[] crc;

			packet = generatePacket();
			crc = SnifferUtils.computeFCS(packet);
			((AppSniffer154) getApplication()).addPacket(sessionUri, packet,
					crc, true);
			mHandler.postDelayed(periodicTask, PERIOD);
		}

		/**
		 * Generate a random IEEE 802.15.4 frame
		 * 
		 * @return a IEEE 802.15.4 frame
		 */
		private byte[] generatePacket() {
			byte[] packet;

			packet = PACKETS[(int) (count % PACKETS.length)];
			count++;
			return packet;
		}
	};

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.app.Service#onBind(android.content.Intent)
	 */
	@Override
	public IBinder onBind(Intent intent) {
		return mBinder;
	}

	// 00 00 00 11 [b] 0x03
	private final static byte[] COMMAND_BEACON_REQUEST = { 0x03, 0x08, 0x06,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x07 };
	// 00 00 00 00 [b] 0x00
	private final static byte[] BEACON = { 0x00, (byte) 0x80, 0x63,
			(byte) 0xff, 0x01, 0x00, 0x00, (byte) 0xff, (byte) 0xcf, 0x00,
			0x00, 0x00, 0x20, (byte) 0x84, 0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72,
			0x00, 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x00 };
	// 00 00 00 10 [b] 0x02
	private final static byte[] ACK = { 0x02, 0x00, 0x0c };
	// 01 10 00 01
	private final static byte[] DATA = { 0x61, (byte) 0x88, 0x12, (byte) 0xff,
			0x01, 0x00, 0x00, 0x4d, 0x2c, 0x48, 0x02, 0x00, 0x00, 0x4d, 0x2c,
			0x1e, 0x7d, 0x28, 0x03, 0x00, 0x00, 0x00, 0x07, 0x20, 0x00,
			(byte) 0xff, (byte) 0xff, (byte) 0xda, 0x1c, 0x00, 0x00, 0x16,
			0x60, (byte) 0x9d, 0x76, (byte) 0xeb, 0x48, 0x28, 0x33, 0x40, 0x43,
			(byte) 0xfd, (byte) 0xd0, 0x2a, (byte) 0xa5, (byte) 0x85, 0x37,
			(byte) 0xfe, (byte) 0xd3, 0x2c, (byte) 0xc5, 0x28, 0x7b, 0x59,
			(byte) 0xdf, 0x75, (byte) 0x80, 0x1e };
	// 00 10 00 11 [b] 0x23
	private final static byte[] COMMAND_ASSOCIATION_REQ = { 0x23, (byte) 0xc8,
			0x0c, (byte) 0xff, 0x01, 0x00, 0x00, (byte) 0xff, (byte) 0xff,
			0x07, 0x20, 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xda, 0x1c,
			0x00, 0x01, (byte) 0xce };
	private static final byte[][] PACKETS = { COMMAND_BEACON_REQUEST, BEACON,
			ACK, DATA, COMMAND_ASSOCIATION_REQ };

	@Override
	public boolean startSniffing(byte channelId) {
		sessionUri = ((AppSniffer154) getApplication()).createNewSession();
		mHandler.postDelayed(periodicTask, PERIOD);
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see it.sssup.rtn.sniffer154.sniffing.ISnifferService#stopSniffing()
	 */
	@Override
	public boolean stopSniffing() {
		mHandler.removeCallbacks(periodicTask);
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.app.Service#onDestroy()
	 */
	@Override
	public void onDestroy() {
		super.onDestroy();
		stopSniffing();
	}

}
