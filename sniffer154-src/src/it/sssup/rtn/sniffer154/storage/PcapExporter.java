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
package it.sssup.rtn.sniffer154.storage;

import it.sssup.rtn.sniffer154.AppSniffer154;
import it.sssup.rtn.sniffer154.R;
import it.sssup.rtn.sniffer154.dissecting.Packet80215;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.text.Editable;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class PcapExporter extends Activity {
	// private final static int LINKTYPE_IEEE802_15_4 = 195;
	// TODO add an option for FCS packets
	private final static int LINKTYPE_IEEE802_15_4_NOFCS = 230;
	private static final String TAG = "PCAPFILEMANAGER";
	private static final String PCAPEXT = ".pcap";

	private static Uri sessionUri = Uri.EMPTY;
	private int sessionDateBase;
	public Cursor cursor;

	private class GlobalHeader {
		static final int magic_number = 0xa1b2c3d4; /* magic number */
		static final short version_major = 2;
		static final short version_minor = 4;
		static final int thiszone = 0; /* GMT to local correction */
		static final int sigfigs = 0; /* accuracy of timestamps */
		static final int snaplen = 65535; /*
										 * max length of captured packets, in
										 * octets
										 */
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		// Be sure to call the super class.
		super.onCreate(savedInstanceState);
		Log.d(TAG, "onCreate()");
		setContentView(R.layout.exporter);
		final Button saveButton = (Button) findViewById(R.id.buttonExport);
		AppSniffer154 app = (AppSniffer154) getApplication();
		sessionUri = app.getSessionUri();
		Cursor sessionC = getContentResolver().query(sessionUri, null, null,
				null, null);
		if (sessionC == null || !sessionC.moveToFirst()) {
			toastMessage("Error, Cannot find the session date");
			saveButton.setEnabled(false);
			return;
		}

		long sessionDate = sessionC.getLong(sessionC
				.getColumnIndex(SessionTable.C_SESSION_DATE));
		sessionDateBase = (int) (sessionDate / 1000);

		Uri uri = Uri.withAppendedPath(sessionUri,
				PacketContentProvider.BASE_PATH_PACKETS + "/"
						+ PacketContentProvider.BASE_PATH_FILTERED);
		cursor = getContentResolver().query(uri, null, null, null, null);
		if (cursor == null) {
			saveButton.setEnabled(false);
		}
		saveButton.setEnabled(true);
		saveButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				saveClicked(v);
			}
		});
	}

	private void saveClicked(View v) {
		Log.d(TAG, "exportListButton()");
		exportList();
	}

	private void writeGlobalHeader(DataOutputStream dos, int LINKTYPE)
			throws IOException {
		dos.writeInt(GlobalHeader.magic_number);
		dos.writeShort(GlobalHeader.version_major);
		dos.writeShort(GlobalHeader.version_minor);
		dos.writeInt(GlobalHeader.thiszone);
		dos.writeInt(GlobalHeader.sigfigs);
		dos.writeInt(GlobalHeader.snaplen);
		dos.writeInt(LINKTYPE);
	}

	private void writeRecord(DataOutputStream dos, Packet80215 pack, long ts)
			throws IOException {
		int secOffset = (int) (ts / 1000);
		int us = ((int) (ts % 1000)) * 1000;
		dos.writeInt(secOffset + sessionDateBase);
		dos.writeInt(us);
		dos.writeInt(pack.getRaw().length);
		dos.writeInt(pack.getRaw().length);
		dos.write(pack.getRaw());
	}

	private void toastMessage(String mess) {
		Toast toast = Toast.makeText(getApplicationContext(), mess, Toast.LENGTH_LONG);
		toast.show();
	}

	private void exportList() {
		Log.d(TAG, "ExportList");
		if (!cursor.moveToFirst()) { // empty list
			toastMessage("Empty list");
			return;
		}

		EditText e = (EditText) findViewById(R.id.editText1);

		long sessionID = cursor.getLong(cursor
				.getColumnIndex(PacketTable.C_PACKET_SESSION));

		String fileName = "Session" + Long.toString(sessionID);

		Editable s = e.getText();
		if (!s.toString().equals("")) {
			fileName = s.toString();
		}

		String fullFileName = fileName + PCAPEXT;
		File dir = new File(Environment.getExternalStorageDirectory()
				+ "/sniffer154/");
		dir.mkdirs();
		File file = new File(dir, fullFileName);
		try {
			file.createNewFile();
			if (!file.canWrite()) {
				Log.d(TAG, "cannot write");
				toastMessage("Error writing to file");
				return;
			}
			if (!file.exists()) {
				Log.d(TAG, "not exists");
				toastMessage("Unable to create file");
				return;
			}

			FileOutputStream fos;

			fos = new FileOutputStream(file);
			DataOutputStream dos = new DataOutputStream(fos);
			int linktype = LINKTYPE_IEEE802_15_4_NOFCS;
			writeGlobalHeader(dos, linktype);
			do {
				byte[] packet = cursor.getBlob(cursor
						.getColumnIndex(PacketTable.C_PACKET_PAYLOAD));
				Packet80215 pack = Packet80215.create(packet);
				long tsOffset = cursor.getLong(cursor
						.getColumnIndex(PacketTable.C_PACKET_DATE));

				if (pack == null) {
					toastMessage("Error parsing packet");
					return;
				}
				Log.d(TAG, "Exporting " + pack.getType());

				writeRecord(dos, pack, tsOffset);
			} while (cursor.moveToNext());
			dos.close();
			toastMessage("File " + fullFileName + " saved");
		} catch (FileNotFoundException e1) {
			Log.d(TAG, "FileNotFound");
			toastMessage("File not found");
			e1.printStackTrace();
			return;
		} catch (IOException e2) {
			Log.d(TAG, "IOException");
			toastMessage("Error writing to file");
			e2.printStackTrace();
		}
	}
}
