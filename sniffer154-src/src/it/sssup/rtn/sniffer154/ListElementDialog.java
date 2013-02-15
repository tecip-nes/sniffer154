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

import it.sssup.rtn.sniffer154.dissecting.Packet80215;
import it.sssup.rtn.sniffer154.storage.PacketContentProvider;
import it.sssup.rtn.sniffer154.storage.PacketTable;
import android.app.Activity;
import android.app.LoaderManager.LoaderCallbacks;
import android.content.CursorLoader;
import android.content.Loader;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

public class ListElementDialog extends Activity {

	/* Static fields */
	public static final String POSITION = "position";
	public static final String SESSION_ID = "sessionId";

	@SuppressWarnings("unused")
	private static final String TAG = ListElementDialog.class.getSimpleName();

	/* fields */
	private int pos = 0;
	public Cursor cursor;
	public boolean updateRequired = false;
	private TextView textTime;
	private TextView textType;
	private TextView textSeq;
	private ViewGroup viewGroupInsertPoint;
	private Button buttonPrev;
	private Button buttonNext;

	/* Public Methods */
	public void showNext(View view) {
		pos++;
		updateRequired = true;
		updateView();
	}

	public void showPrevious(View view) {
		pos--;
		updateRequired = true;
		updateView();
	}

	/* Private Methods */

	private void updateView() {
		buttonNext.setEnabled(pos < cursor.getCount() - 1);
		if (!updateRequired)
			return;
		buttonPrev.setEnabled(pos > 0);
		cursor.moveToPosition(pos);
		long time = cursor.getLong(cursor
				.getColumnIndex(PacketTable.C_PACKET_DATE));
		byte[] packet = cursor.getBlob(cursor
				.getColumnIndex(PacketTable.C_PACKET_PAYLOAD));
		Packet80215 pack = Packet80215.create(packet);
		String timeString = time / 1000 + "." + time % 1000;
		textTime.setText("TS = " + timeString);
		textType.setText(pack.getType());
		textSeq.setText("SEQ = " + pack.getSeqNo());
		View v = pack.createDetailView(this);
		viewGroupInsertPoint.removeAllViews();
		if (v != null) {
			viewGroupInsertPoint.addView(v, 0, new ViewGroup.LayoutParams(
					ViewGroup.LayoutParams.FILL_PARENT,
					ViewGroup.LayoutParams.FILL_PARENT));
		}
		updateRequired = false;
	}

	/* Activity implementation */
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		// Be sure to call the super class.
		super.onCreate(savedInstanceState);

		setContentView(R.layout.list_dialog_activity);
		Bundle extras = getIntent().getExtras();
		pos = extras.getInt(POSITION);

		textTime = (TextView) findViewById(R.id.packetTime);
		textType = (TextView) findViewById(R.id.packetType);
		textSeq = (TextView) findViewById(R.id.packetSeq);
		viewGroupInsertPoint = (ViewGroup) findViewById(R.id.insert_point);
		buttonPrev = (Button) findViewById(R.id.buttonPrev);
		buttonNext = (Button) findViewById(R.id.buttonNext);
		updateRequired = true;
		// start loader
		getLoaderManager().restartLoader(0, extras,
				new DetailCallBacks());
	}

	/* Cursor Loader Callback */
	class DetailCallBacks implements LoaderCallbacks<Cursor> {

		@Override
		public Loader<Cursor> onCreateLoader(int id, Bundle args) {
			long sessionId = args.getLong(SESSION_ID);
			Uri uri = Uri.withAppendedPath(PacketContentProvider.SESSIONS_URI,
					sessionId + "/" + PacketContentProvider.BASE_PATH_PACKETS
							+ "/" + PacketContentProvider.BASE_PATH_FILTERED);
			CursorLoader cursorLoader = new CursorLoader(
					ListElementDialog.this, uri, null, null, null, null);
			return cursorLoader;
		}

		@Override
		public void onLoadFinished(Loader<Cursor> loader, Cursor data) {
			cursor = data;
			updateView();
		}

		@Override
		public void onLoaderReset(Loader<Cursor> loader) {
			cursor = null;
		}
	}
}
