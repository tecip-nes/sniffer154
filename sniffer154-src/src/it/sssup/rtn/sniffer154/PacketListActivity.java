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
import it.sssup.rtn.sniffer154.prefs.FilterPrefActivity;
import it.sssup.rtn.sniffer154.prefs.PrefActivity;
import it.sssup.rtn.sniffer154.storage.PacketContentProvider;
import it.sssup.rtn.sniffer154.storage.PacketTable;
import it.sssup.rtn.sniffer154.storage.PcapExporter;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.LoaderManager.LoaderCallbacks;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.CursorLoader;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.Loader;
import android.content.res.Configuration;
import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.CursorAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ToggleButton;

/**
 * The main activity of this application
 * 
 * @author Daniele Alessandrelli
 * @author Andrea Azzarà
 * 
 */
public class PacketListActivity extends Activity implements
		OnClickListener {

	@SuppressWarnings("unused")
	private static final String TAG = PacketListActivity.class.getSimpleName();

	/**
	 * Every cursors loader needs an ID
	 */
	private static final int PACKET_CURSOR_LOADER = 0;

	/**
	 * The adapter for the ListView displaying captured packets
	 */
	private PacketCursorAdapter adapter;

	// views
	private ListView listViewPacket;
	private CheckBox checkButtonAutoscroll;
	private ContentObserver sessionContentObserver;
	private LoaderCallbacks<Cursor> packetListViewLoaderCallbacks = new PacketListViewLoaderCallbacks();
	private ToggleButton toggleFiltering;

	/*----------------------------------------------------------------------- */
	/*------------------------- Activity Methods -----------------------------*/
	/*------------------------------------------------------------------------*/

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.support.v4.app.FragmentActivity#onCreate(android.os.Bundle)
	 */
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		AppSniffer154 app;
		
		super.onCreate(savedInstanceState);
		app = (AppSniffer154) getApplication();
		
		app.checkForSnifferAttachedAction(getIntent());
			
		setContentView(R.layout.packet_list);
		findViewById(R.id.toggleCapture).setOnClickListener(this);
		findViewById(R.id.toggleFilter).setOnClickListener(this);
		checkButtonAutoscroll = (CheckBox) findViewById(R.id.checkBoxAutoScroll);
		checkButtonAutoscroll.setChecked(true);
		checkButtonAutoscroll
				.setOnCheckedChangeListener(new AutoscrollOnCheckedChangeListener());
		toggleFiltering = (ToggleButton) findViewById(R.id.toggleFilter);
		// be notified when the current session changes
		sessionContentObserver = new SessionContentObserver(new Handler());

		// set up the packet list
		listViewPacket = (ListView) findViewById(R.id.listViewPacket);
		listViewPacket
				.setOnItemClickListener(new PacketListViewOnItemClickListener());
		setUpCursorLoader();
	}
	
	/* (non-Javadoc)
	 * @see android.app.Activity#onDestroy()
	 */
	@Override
	protected void onDestroy() {
		findViewById(R.id.toggleCapture).setOnClickListener(null);
		findViewById(R.id.toggleFilter).setOnClickListener(null);
		checkButtonAutoscroll.setOnCheckedChangeListener(null);
		sessionContentObserver = null;
		listViewPacket.setOnItemClickListener(null);
		clearCursorLoader();
		super.onDestroy();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.support.v4.app.FragmentActivity#onResume()
	 */
	@Override
	protected void onResume() {
		super.onResume();

		IntentFilter filter;
		
		getContentResolver().registerContentObserver(
				PacketContentProvider.SESSIONS_URI, false,
				sessionContentObserver);
		updateCaptureButton();
		boolean b = getSharedPreferences(AppSniffer154.PREFS_FILTER, 0)
				.getBoolean(getString(R.string.prefsFilterEnableKey), false);
		toggleFiltering.setChecked(b);
		filter = new IntentFilter(AppSniffer154.ACTION_SNIFFING_STATE_CHANGED);
		this.registerReceiver(receiver, filter);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.support.v4.app.FragmentActivity#onPause()
	 */
	@Override
	protected void onPause() {
		super.onPause();
		this.unregisterReceiver(receiver);
		getContentResolver().unregisterContentObserver(sessionContentObserver);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.support.v4.app.FragmentActivity#onConfigurationChanged(android
	 * .content.res.Configuration)
	 */
	@Override
	public void onConfigurationChanged(Configuration newConfig) {
		// called when screen is rotated
		super.onConfigurationChanged(newConfig);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.app.Activity#onCreateOptionsMenu(android.view.Menu)
	 */
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		getMenuInflater().inflate(R.menu.menu, menu);
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.app.Activity#onPrepareOptionsMenu(android.view.Menu)
	 */
	@Override
	public boolean onPrepareOptionsMenu(Menu menu) {
		AppSniffer154 app = (AppSniffer154) getApplication();
		MenuItem item = menu.findItem(R.id.itemToggleTestMode);
		if (app.isTestModeEnblad()) {
			item.setTitle(R.string.titleTestModeDisable);
		} else {
			item.setTitle(R.string.titleTestModeEnable);
		}
		item = menu.findItem(R.id.itemExport);
		if (!app.isSniffingInProgress()
				&& !app.getSessionUri().equals(Uri.EMPTY))
			item.setEnabled(true);
		else
			item.setEnabled(false);
		item = menu.findItem(R.id.itemManageSessions);
		item.setEnabled(!app.isSniffingInProgress());
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.support.v4.app.FragmentActivity#onMenuItemSelected(int,
	 * android.view.MenuItem)
	 */
	@Override
	public boolean onMenuItemSelected(int featureId, MenuItem item) {
		switch (item.getItemId()) {
		case R.id.itemToggleTestMode:
			toggleTestMode();
			return true;
		case R.id.itemExport:
			startExportActivity();
			return true;
		case R.id.itemManageSessions:
			startManageSessionsActivity();
			return true;
		case R.id.itemOptions:
			startActivity(new Intent(this, PrefActivity.class));
		default:
			return false;
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.support.v4.app.FragmentActivity#onActivityResult(int, int,
	 * android.content.Intent)
	 */
	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		super.onActivityResult(requestCode, resultCode, data);
		if (resultCode == SessionManagerActivity.LOAD) {
			setUpCursorLoader();
		}
	}

	/*------------------------------------------------------------------------*/
	/*----------------------- OnClickListener Methods ------------------------*/
	/*------------------------------------------------------------------------*/

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.view.View.OnClickListener#onClick(android.view.View)
	 */
	@Override
	public void onClick(View view) {
		Intent intent = null;
		AppSniffer154 app = (AppSniffer154) getApplication();
		switch (view.getId()) {
		case R.id.toggleCapture:
			ToggleButton tb = (ToggleButton) view;
			if (tb.isChecked()) {
				listViewPacket.setAdapter(null);
				app.startSniffing(this);
			} else {
				app.stopSniffing(this);
			}
			break;
		case R.id.toggleFilter:
			toggleFiltering.toggle();
			intent = new Intent(this, FilterPrefActivity.class);
			startActivity(intent);
		}
	}

	/*------------------------------------------------------------------------*/
	/*-------------------------- Private Methods -----------------------------*/
	/*------------------------------------------------------------------------*/

	/**
	 * Sets up a CursorLoader for updating the list of captured packets
	 */
	private void setUpCursorLoader() {
		adapter = new PacketCursorAdapter(this, null, 0);
		listViewPacket.setAdapter(adapter);
		getLoaderManager().restartLoader(PACKET_CURSOR_LOADER, null,
				packetListViewLoaderCallbacks);
	}
	
	/**
	 * Sets up a CursorLoader for updating the list of captured packets
	 */
	private void clearCursorLoader() {
		listViewPacket.setAdapter(adapter);
		getLoaderManager().destroyLoader(PACKET_CURSOR_LOADER);
		listViewPacket.setAdapter(null);
		adapter = null;
	}

	/**
	 * Updates the status of the "Capture" button.
	 * 
	 * The button is checked if a capture is in progress, unchecked otherwise.
	 * The button is enabled if a sniffer is attached to the android device,
	 * disabled otherwise
	 */
	private void updateCaptureButton() {
		AppSniffer154 app = (AppSniffer154) getApplication();
		ToggleButton tb = (ToggleButton) findViewById(R.id.toggleCapture);
		tb.setChecked(app.isSniffingInProgress());
		tb.setEnabled(app.isSniffingEnabled());
	}

	/**
	 * Toggles the test mode
	 */
	private void toggleTestMode() {
		AppSniffer154 app = (AppSniffer154) getApplication();
		app.toggleTestMode();
		updateCaptureButton();
	}

	/**
	 * Starts the activity to export the packets currently displayed
	 */
	private void startExportActivity() {
		Intent intent = new Intent(this, PcapExporter.class);
		startActivity(intent);
	}

	/**
	 * Starts the activity to manage (open / delete / export) previous sniffing
	 * sessions
	 */
	private void startManageSessionsActivity() {
		Intent intent = new Intent(this, SessionManagerActivity.class);
		startActivityForResult(intent, 0);
	}

	/**
	 * Starts the activity for showing packet details
	 * 
	 * @param pos
	 *            - the position of the packet in the cursor (we use the
	 *            position instead of the packet ID, because in this way we can
	 *            move from one packet to the other using next and prev buttons)
	 * @param sessionId
	 *            - the session id of the packet
	 */
	private void showPacketDetails(int pos, long sessionId) {
		Intent intent = new Intent(this, ListElementDialog.class);
		intent.putExtra(ListElementDialog.POSITION, pos);
		intent.putExtra(ListElementDialog.SESSION_ID, sessionId);
		startActivity(intent);
	}

	/**
	 * A class implementing the OnCheckedChangeListener for the auto-scroll
	 * checkbox
	 */
	private class AutoscrollOnCheckedChangeListener implements
			OnCheckedChangeListener {
		public void onCheckedChanged(CompoundButton buttonView,
				boolean isChecked) {
			if (isChecked) {
				Toast.makeText(getApplicationContext(), "Autoscroll On",
						Toast.LENGTH_SHORT).show();
				listViewPacket
						.setTranscriptMode(ListView.TRANSCRIPT_MODE_ALWAYS_SCROLL);
			} else {
				Toast.makeText(getApplicationContext(), "Autoscroll Off",
						Toast.LENGTH_SHORT).show();
				listViewPacket
						.setTranscriptMode(ListView.TRANSCRIPT_MODE_DISABLED);
			}
		}
	}

	/**
	 * A class to observe changes of the SESSION_URI:
	 * content://it.retis.rtn.sniffer154.contentprovider/sessions
	 * 
	 * Every time a new session is created the packet list is updated
	 * 
	 * @author Daniele Alessandrelli
	 * 
	 */
	private class SessionContentObserver extends ContentObserver {

		/**
		 * onChange() will happen on the provider Handler.
		 * 
		 * @param handler
		 *            The handler to run {@link #onChange(boolean)} on.
		 * 
		 * @see android.database.ContentObserver#ContentObserver(Handler)
		 */
		public SessionContentObserver(Handler handler) {
			super(handler);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see android.database.ContentObserver#onChange(boolean)
		 */
		@Override
		public void onChange(boolean selfChange) {
			super.onChange(selfChange);
			setUpCursorLoader(); // update the cursor list
		}
	}

	/**
	 * The callback which is called when a packet is clicked. Packet details are
	 * shown upon user click
	 * 
	 */
	private class PacketListViewOnItemClickListener implements
			OnItemClickListener {

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.widget.AdapterView.OnItemClickListener#onItemClick(android
		 * .widget.AdapterView, android.view.View, int, long)
		 */
		@Override
		public void onItemClick(AdapterView<?> parent, View view, int position,
				long id) {
			Cursor cur = (Cursor) adapter.getItem(position);
			Long pid = cur.getLong(cur
					.getColumnIndex(PacketTable.C_PACKET_SESSION));
			showPacketDetails(position, pid);
		}
	}

	/**
	 * The LoaderCallbacks class for the cursor loader used for loading packets
	 * from the database
	 * 
	 * @author Daniele Alessandrelli
	 * 
	 */
	private class PacketListViewLoaderCallbacks implements
			LoaderCallbacks<Cursor> {

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.support.v4.app.LoaderManager.LoaderCallbacks#onCreateLoader
		 * (int, android.os.Bundle)
		 */
		@Override
		public Loader<Cursor> onCreateLoader(int id, Bundle args) {
			AppSniffer154 app;
			Uri uri;
			CursorLoader cursorLoader;

			app = (AppSniffer154) getApplication();
			uri = app.getSessionUri();
			if (!uri.equals(Uri.EMPTY)) {
				uri = Uri.withAppendedPath(uri,
						PacketContentProvider.BASE_PATH_PACKETS + "/"
								+ PacketContentProvider.BASE_PATH_FILTERED);
			}
			cursorLoader = new CursorLoader(PacketListActivity.this, uri, null,
					null, null, null);

			return cursorLoader;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.support.v4.app.LoaderManager.LoaderCallbacks#onLoadFinished
		 * (android.support.v4.content.Loader, java.lang.Object)
		 */
		@Override
		public void onLoadFinished(Loader<Cursor> loader, Cursor cursor) {
			Cursor oldCursor;
			
			oldCursor = adapter.swapCursor(cursor);
			if (oldCursor != null)
				oldCursor.close();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.support.v4.app.LoaderManager.LoaderCallbacks#onLoaderReset
		 * (android.support.v4.content.Loader)
		 */
		@Override
		public void onLoaderReset(Loader<Cursor> cursor) {
			Cursor oldCursor;
			
			oldCursor = adapter.swapCursor(null);
			if (oldCursor != null)
				oldCursor.close();
		}
	}

	/**
	 * CursorAdapter for binding the row of the packet list with the content of
	 * a packet
	 * 
	 * @author Daniele Alessandrelli
	 * 
	 */
	private static class PacketCursorAdapter extends CursorAdapter {

		private final LayoutInflater mInflater;

		/**
		 * Constructs a PacketCursorAdapter object
		 * 
		 * @param context
		 *            The context
		 * @param cursor
		 *            The cursor from which to get the data.
		 * @param flags
		 *            Flags used to determine the behavior of the adapter; may
		 *            be any combination of FLAG_AUTO_REQUERY and
		 *            FLAG_REGISTER_CONTENT_OBSERVER.
		 * 
		 */
		public PacketCursorAdapter(Context context, Cursor cursor, int flags) {
			super(context, cursor, flags);
			mInflater = LayoutInflater.from(context);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.support.v4.widget.CursorAdapter#newView(android.content.Context
		 * , android.database.Cursor, android.view.ViewGroup)
		 */
		@Override
		public View newView(Context context, Cursor cursor, ViewGroup parent) {
			final View view = mInflater.inflate(R.layout.packet_row, parent,
					false);
			return view;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.support.v4.widget.CursorAdapter#bindView(android.view.View,
		 * android.content.Context, android.database.Cursor)
		 */
		@SuppressLint("DefaultLocale")
		@Override
		public void bindView(View view, Context context, Cursor cursor) {
			ViewHolder holder = (ViewHolder) view.getTag();
			if (holder == null) {
				holder = new ViewHolder();
				holder.textDate = (TextView) view.findViewById(R.id.textDate);
				holder.textType = (TextView) view
						.findViewById(R.id.packet_type);
				holder.textLen = (TextView) view.findViewById(R.id.packet_len);
				holder.textSrc = (TextView) view
						.findViewById(R.id.packet_source);
				holder.textDst = (TextView) view.findViewById(R.id.packet_dest);

				holder.columnDate = cursor
						.getColumnIndexOrThrow(PacketTable.C_PACKET_DATE);
				holder.columnPayload = cursor
						.getColumnIndexOrThrow(PacketTable.C_PACKET_PAYLOAD);
				view.setTag(holder);
			}
			// payload
			byte[] payload = cursor.getBlob(holder.columnPayload);
			Packet80215 p = Packet80215.create(payload);
			holder.textType.setText(p.getType());
			holder.textLen.setText(Integer.toString(payload.length));
			holder.textSrc.setText((p.getSourceAddress() < 0) ? "-" : "0x"
					+ Long.toHexString(p.getSourceAddress()).toUpperCase());
			holder.textDst.setText((p.getDstAddress() < 0) ? "-" : "0x"
					+ Long.toHexString(p.getDstAddress()).toUpperCase());
			Long time = cursor.getLong(holder.columnDate);
			holder.textDate.setText(time / 1000 + "." + time % 1000);
		}

		/**
		 * A class to hold references to views and column indexes
		 * 
		 * @author Daniele Alessandrelli
		 * 
		 */
		private static class ViewHolder {
			TextView textDate;
			TextView textType;
			TextView textLen;
			TextView textSrc;
			TextView textDst;
			int columnDate;
			int columnPayload;
		}

	}

	/**
	 * A broadcast receiver for receiving ACTION_SNIFFING_STATE_CHANGED
	 */
	private final BroadcastReceiver receiver = new BroadcastReceiver() {

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.content.BroadcastReceiver#onReceive(android.content.Context,
		 * android.content.Intent)
		 */
		@Override
		public void onReceive(Context context, Intent intent) {
			updateCaptureButton();
		}

	}; // receiver

}
