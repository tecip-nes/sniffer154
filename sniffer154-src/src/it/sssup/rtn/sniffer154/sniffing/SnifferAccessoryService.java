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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;

import android.app.Service;
import android.content.Intent;
import android.net.Uri;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.util.Log;
import it.sssup.retis.retisusbaccessory.RetisAccessoryService;
import it.sssup.rtn.sniffer154.AppSniffer154;

public class SnifferAccessoryService extends RetisAccessoryService implements
		ISnifferService {

	private static final String TAG = SnifferAccessoryService.class
			.getSimpleName();
	private static final String ACTION_USB_PERMISSION = "it.sssup.rtn.usbaccessory.heartrate";
	private static final byte MAC_FRAME = 0;
	private static final byte CMD_SET_CHANNEL = 1;
	private static final byte CMD_STOP = 2;

	private final MyHandler mHandler = new MyHandler(this);
	private final IBinder mBinder = new SnifferBinder(this);

	@Override
	protected Handler getAccessoryHandler() {
		return mHandler;
	}

	@Override
	protected String getActionUsbPermisison() {
		return ACTION_USB_PERMISSION;
	}

	/**
	 * Starts sniffing
	 * 
	 * @param channelId
	 *            - the channel to sniff
	 * @return true if sniffing was correctly started
	 */
	public boolean startSniffing(byte channelId) {
		boolean retv;
		AppSniffer154 app;

		try {
			app = (AppSniffer154) getApplication();
			mHandler.setSessionUri(app.createNewSession());
			accessoryWrite(CMD_SET_CHANNEL, new byte[] { channelId });
			retv = true;
		} catch (IOException e) {
			Log.d(TAG, "Error writing to accessory", e);
			retv = false;
		}
		return retv;
	}

	/**
	 * Stops sniffing
	 * 
	 * @return true if sniffing was correctly stopped
	 */
	public boolean stopSniffing() {
		boolean retv;

		try {
			accessoryWrite(CMD_STOP, new byte[0]);
			retv = true;
		} catch (IOException e) {
			Log.d(TAG, "Error writing to accessory", e);
			retv = false;
		}
		return retv;
	}

	@Override
	public IBinder onBind(Intent arg0) {
		return mBinder;
	}

	private static class MyHandler extends Handler {

		WeakReference<Service> mService;
		Uri mSessionUri;

		public MyHandler(Service service) {
			mService = new WeakReference<Service>(service);
		}
		
		private void setSessionUri(Uri sessionUri) {
			mSessionUri = sessionUri;
		}

		@Override
		public void handleMessage(Message msg) {
			Service service;
			AppSniffer154 app;
			byte[] data;

			service = mService.get();
			if (service != null) {
				Log.d(TAG, "UsbMessageHandler::handleMessage(), what = "
						+ msg.what);

				app = (AppSniffer154) service.getApplication();
				data = msg.getData().getByteArray(
						RetisAccessoryService.MSG_PAYLAOD);
				switch (msg.what) {
				case MAC_FRAME:
					if (mSessionUri != null) {
						InputStream in = new ByteArrayInputStream(data);
						try {
							SnifferUtils.parseInPkt(in, mSessionUri, app);
						} catch (IOException e) {
							// should never happen
							e.printStackTrace();
						}
					}
					break;
				}
			}
		}
	}

}
